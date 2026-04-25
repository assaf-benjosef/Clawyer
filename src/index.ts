/**
 * Clawyer — OpenClaw Plugin Entry Point
 *
 * Registers two things:
 * 1. `clawyer_justify` tool — agent calls this to provide justification + exact params
 * 2. `before_tool_call` hook — thin gate that verifies params match and triggers HITL
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Type } from "@sinclair/typebox";
import {
  evaluateToolPolicy,
  isToolProtected,
  hashParams,
  buildApprovalContext,
} from "./matcher.js";
import type {
  ClawyerConfig,
  PoliciesConfig,
  StoredJustification,
} from "./types.js";

// ─── Module-Scope Shared State ───────────────────────────────────────────────
// Shared between the clawyer_justify tool and the before_tool_call hook.
// Keyed by sessionKey for isolation between concurrent sessions.
const justificationStore = new Map<string, StoredJustification>();

/** Max age for stored justifications (5 minutes). */
const JUSTIFICATION_TTL_MS = 5 * 60 * 1000;

// ─── Default Config ──────────────────────────────────────────────────────────

const DEFAULT_CONFIG: PoliciesConfig = {
  default: "allow",
  rules: [
    {
      tools: ["exec"],
      mode: "human_approval",
      // dangerousCommands omitted → built-in defaults
    },
  ],
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function textResult(text: string) {
  return {
    content: [{ type: "text" as const, text }],
    details: { status: "ok" as const },
  };
}

// ─── Plugin Entry ────────────────────────────────────────────────────────────

export default definePluginEntry({
  id: "clawyer",
  name: "Clawyer — Semantic Security Guardrail",
  description:
    "Intercepts sensitive tool calls and requires human approval with semantic context before execution.",

  register(api) {
    const rawConfig = api.pluginConfig as ClawyerConfig | undefined;
    const policies: PoliciesConfig = rawConfig?.policies ?? DEFAULT_CONFIG;

    api.logger.info(
      `Clawyer loaded: ${policies.rules.length} rule(s), default="${policies.default}"`
    );

    // ── 1. Register clawyer_justify Tool ───────────────────────────────────

    api.registerTool({
      name: "clawyer_justify",
      label: "Clawyer Justify",
      description:
        "Security guardrail: You MUST call this tool before using any protected tool (like exec). Provide the exact tool name, the exact parameters you intend to use, and a justification explaining why this action is needed.",
      parameters: Type.Object({
        tool: Type.String({
          description: "The name of the tool you intend to call (e.g. 'exec').",
        }),
        params: Type.String({
          description: "A JSON string representing the EXACT parameters you will pass to the tool. E.g. '{\"command\": \"rmdir /tmp/foo\"}'.",
        }),
        justification: Type.String({
          description: "Your reasoning for why this action is needed. This will be shown to the human operator.",
        }),
      }),

      execute: async (toolCallId: string, args: Record<string, unknown>) => {
        const tool = args.tool as string;
        const justification = args.justification as string;
        
        let params: Record<string, unknown>;
        try {
          params = typeof args.params === "string" 
            ? JSON.parse(args.params) 
            : Object(args.params);
        } catch (e) {
          return textResult(`Clawyer error: Unparseable params JSON (${e}). Please provide a valid JSON string.`);
        }

        // Run heuristic pre-check
        const decision = evaluateToolPolicy(tool, params, policies);

        if (decision === "block") {
          return textResult(
            `🚫 Clawyer: "${tool}" is blocked by policy. Do not attempt this action.`
          );
        }

        // Derive a sessionKey from the toolCallId (fallback)
        // The real sessionKey will be available in the hook via ctx
        const storeKey = toolCallId;

        // Store the justification with params hash for binding
        const entry: StoredJustification = {
          tool,
          paramsHash: hashParams(tool, params),
          justification,
          decision,
          timestamp: Date.now(),
        };
        justificationStore.set(storeKey, entry);

        if (decision === "allow") {
          return textResult(
            `✅ Clawyer: Pre-approved. You may now call "${tool}" with the specified parameters.`
          );
        }

        // decision === "needs_approval"
        return textResult(
          `⏸️ Clawyer: Justification recorded. ` +
          `Now call "${tool}" with the EXACT same parameters — a human will be asked to approve.`
        );
      },
    });

    // ── 2. The before_tool_call Hook (Thin Enforcement Gate) ───────────────

    api.on("before_tool_call", (event, ctx) => {
      const { toolName, params: toolParams } = event;
      const sessionKey = ctx.sessionKey ?? ctx.runId ?? "default";
      const args = (toolParams as Record<string, unknown>) ?? {};

      // Skip our own tool
      if (toolName === "clawyer_justify") {
        return;
      }

      // Check policy directly in the hook
      const decision = evaluateToolPolicy(toolName, args, policies);

      // If the policy allows it implicitly (e.g. safe exec command), let it through!
      // No justification required.
      if (decision === "allow") {
        return;
      }

      // If it's hard-blocked by policy
      if (decision === "block") {
        return {
          block: true,
          blockReason: `Clawyer: The tool "${toolName}" is strictly blocked by local policy.`,
        };
      }

      // decision === "needs_approval"
      // ── Protected tool: check store for justification ──

      // Try to find justification — check sessionKey first, then scan by tool name
      let stored = justificationStore.get(sessionKey);

      // Also try scanning all entries for matching tool (handles toolCallId-keyed entries)
      if (!stored) {
        for (const [key, entry] of justificationStore.entries()) {
          if (entry.tool === toolName) {
            stored = entry;
            justificationStore.delete(key);
            break;
          }
        }
      }

      // No justification stored?
      if (!stored) {
        return {
          block: true,
          blockReason:
            `Clawyer: This action is dangerous and requires human approval. ` +
            `You MUST call the "clawyer_justify" tool first. Provide:\n` +
            `- tool: "${toolName}"\n` +
            `- params: <A JSON string of your exact parameters, e.g. "{\\"command\\": \\"rmdir /foo\\"}" >\n` +
            `- justification: "<explain why you need to do this>"\n` +
            `Once the human approves, you can run the actual tool.`,
        };
      }

      // Stored but expired?
      if (Date.now() - stored.timestamp > JUSTIFICATION_TTL_MS) {
        return {
          block: true,
          blockReason:
            `Clawyer: Your previous justification expired. ` +
            `Please call "clawyer_justify" again.`,
        };
      }

      // Stored but wrong tool?
      if (stored.tool !== toolName) {
        return {
          block: true,
          blockReason:
            `Clawyer: Your justification was for "${stored.tool}" but you called "${toolName}". ` +
            `Please call "clawyer_justify" again for this tool.`,
        };
      }

      // Stored but params don't match (anti-cheat)?
      const actualHash = hashParams(toolName, args);
      if (actualHash !== stored.paramsHash) {
        return {
          block: true,
          blockReason:
            `Clawyer: The parameters you're using don't match what you justified. ` +
            `Please call "clawyer_justify" again with the exact parameters you intend to use.`,
        };
      }

      // ── Params verified ──

      if (stored.decision === "allow") {
        // Pre-approved safe command — let through
        return;
      }

      // decision === "needs_approval" → trigger HITL
      const { title, description } = buildApprovalContext(
        toolName,
        args,
        stored.justification
      );

      api.logger.info(`Clawyer: requesting approval for "${toolName}"`);

      return {
        requireApproval: {
          title,
          description,
          severity: "critical" as const,
        },
      };
    });
  },
});
