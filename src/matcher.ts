/**
 * Clawyer — Policy matching, hashing, and approval context utilities.
 */

import type {
  PolicyRule,
  PoliciesConfig,
  JustifyDecision,
} from "./types.js";

// ─── Default Dangerous Commands ──────────────────────────────────────────────

/**
 * Regex patterns matching exec command strings considered dangerous.
 * Users can override per-rule via the `dangerousCommands` config field.
 */
export const DEFAULT_DANGEROUS_COMMANDS: string[] = [
  "\\brm\\b",
  "\\brmdir\\b",
  "\\bunlink\\b",
  "\\bsudo\\b",
  "\\bcurl\\b",
  "\\bwget\\b",
  "\\bchmod\\b",
  "\\bchown\\b",
  "\\bmkfs\\b",
  "\\bdd\\b",
  "\\bshutdown\\b",
  "\\breboot\\b",
  "\\bkill\\b",
  "\\bkillall\\b",
  "\\bpkill\\b",
  "\\bnpm publish\\b",
  "\\bgit push\\b",
  "\\b--force\\b",
  "\\beval\\b",
  "\\bmv\\b",
  "\\b>\\s*/",
  "\\bdrop\\b",
  "\\btruncate\\b",
];

// ─── Tool Name Matching ──────────────────────────────────────────────────────

/**
 * Checks if a tool name matches any of the given glob-like patterns.
 * Supports `*` as a wildcard that matches any characters.
 */
export function matchTool(toolName: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    const regexStr =
      "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*") +
      "$";
    return new RegExp(regexStr, "i").test(toolName);
  });
}

// ─── Command String Matching ─────────────────────────────────────────────────

/**
 * Checks if a command string matches any of the given dangerous patterns.
 */
export function matchCommand(commandStr: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;
  return patterns.some((p) => new RegExp(p, "i").test(commandStr));
}

/**
 * Resolves dangerous command patterns for a rule (custom or defaults).
 */
export function resolveDangerousCommands(rule: PolicyRule): string[] {
  return rule.dangerousCommands ?? DEFAULT_DANGEROUS_COMMANDS;
}

// ─── Extract Command String ──────────────────────────────────────────────────

/**
 * Extracts the command string from exec tool arguments.
 * Handles { cmd: "..." }, { command: "..." }, or first string value.
 */
export function extractExecCommand(
  args: Record<string, unknown>
): string | null {
  if (typeof args.cmd === "string") return args.cmd;
  if (typeof args.command === "string") return args.command;
  for (const val of Object.values(args)) {
    if (typeof val === "string") return val;
  }
  return null;
}

// ─── Params Hashing (Anti-Cheat Binding) ─────────────────────────────────────

/**
 * Creates a deterministic hash string from tool name + params.
 * Used to bind a justification to the exact call the agent intends to make.
 *
 * Uses deep sorted JSON stringification for determinism — no crypto needed
 * since this is an in-memory anti-drift check, not a security primitive.
 */
export function hashParams(
  tool: string,
  params: Record<string, unknown>
): string {
  const canonical = stableStringify({ tool, params });
  // FNV-1a hash for compact, deterministic string
  let hash = 0x811c9dc5;
  for (let i = 0; i < canonical.length; i++) {
    hash ^= canonical.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(36);
}

/** Deep-sorted JSON.stringify for deterministic serialization. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const entries = keys.map(
    (k) => JSON.stringify(k) + ":" + stableStringify((value as Record<string, unknown>)[k])
  );
  return "{" + entries.join(",") + "}";
}

// ─── Approval Context Builder ────────────────────────────────────────────────

/**
 * Builds the human-readable approval prompt.
 * Includes the agent's justification prominently so the human has
 * semantic context for the approval decision.
 */
export function buildApprovalContext(
  toolName: string,
  args: Record<string, unknown>,
  justification: string
): { title: string; description: string } {
  const title = `⚠️ Clawyer: approve "${toolName}"?`;

  // Agent's justification (the whole point of this plugin)
  let description = `**Agent's justification:**\n> ${justification}\n\n`;

  // Technical details
  if (toolName === "exec") {
    const cmd = extractExecCommand(args) ?? JSON.stringify(args);
    description += `**Command:**\n\`\`\`\n${cmd}\n\`\`\``;
  } else {
    const argsStr = Object.entries(args)
      .map(([k, v]) => `  **${k}:** ${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n");
    description += `**Tool:** \`${toolName}\`\n${argsStr}`;
  }

  return { title, description };
}

// ─── Policy Evaluation (for clawyer_justify tool) ────────────────────────────

/**
 * Evaluates a tool call against policies and returns a JustifyDecision.
 * This is called by the clawyer_justify tool to give the agent
 * immediate feedback before it retries the actual tool.
 *
 * Logic:
 * 1. Iterate rules in order; first matching rule wins.
 * 2. mode "block" → "block"
 * 3. mode "human_approval":
 *    a. For exec: check command against dangerous patterns.
 *       Safe command → "allow". Dangerous → "needs_approval".
 *    b. For other tools: always "needs_approval".
 * 4. No rule matches → use default policy.
 */
export function evaluateToolPolicy(
  toolName: string,
  args: Record<string, unknown>,
  config: PoliciesConfig
): JustifyDecision {
  for (const rule of config.rules) {
    if (!matchTool(toolName, rule.tools)) continue;

    if (rule.mode === "block") return "block";

    // mode === "human_approval"
    if (toolName === "exec") {
      const commandStr = extractExecCommand(args);
      if (commandStr !== null) {
        const patterns = resolveDangerousCommands(rule);
        if (!matchCommand(commandStr, patterns)) {
          return "allow"; // safe command like ls, pwd
        }
      }
    }
    return "needs_approval";
  }

  // No rule matched — fall back to default
  return config.default === "block" ? "block" : "allow";
}

// ─── Is Tool Protected? ─────────────────────────────────────────────────────

/**
 * Quick check: does this tool match ANY rule in the config?
 * Used by the hook to decide whether to even check the store.
 */
export function isToolProtected(
  toolName: string,
  config: PoliciesConfig
): boolean {
  return config.rules.some((rule) => matchTool(toolName, rule.tools));
}
