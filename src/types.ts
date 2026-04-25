/**
 * Clawyer — Configuration and state types.
 */

// ─── Policy Config Types ─────────────────────────────────────────────────────

/** Action to take when a tool matches a policy rule. */
export type PolicyMode = "human_approval" | "block";

/** Default action for tools not matching any rule. */
export type DefaultPolicy = "allow" | "block";

/** A single policy rule that matches tools and defines the action. */
export interface PolicyRule {
  /** Tool name patterns to match (supports * wildcards). */
  tools: string[];
  /** Action to take when a tool matches. */
  mode: PolicyMode;
  /**
   * Optional override: regex patterns for exec command arguments.
   * If omitted for exec-type tools, the built-in defaults are used.
   * If provided, replaces the defaults entirely for this rule.
   */
  dangerousCommands?: string[];
}

/** Root policy configuration. */
export interface PoliciesConfig {
  /** Default action for tools not matching any rule. Defaults to "allow". */
  default: DefaultPolicy;
  /** Ordered list of policy rules. First match wins. */
  rules: PolicyRule[];
}

/** Full plugin configuration as read from openclaw.json. */
export interface ClawyerConfig {
  policies: PoliciesConfig;
}

// ─── Justify / Store Types ───────────────────────────────────────────────────

/** The decision made by the heuristic engine during justification. */
export type JustifyDecision = "allow" | "needs_approval" | "block";

/** A stored justification entry waiting to be consumed by the hook. */
export interface StoredJustification {
  /** The tool name the agent intends to call. */
  tool: string;
  /** Deterministic hash of tool + params for anti-cheat binding. */
  paramsHash: string;
  /** The agent's natural-language reasoning. */
  justification: string;
  /** The heuristic decision. */
  decision: JustifyDecision;
  /** Timestamp for TTL / cleanup. */
  timestamp: number;
}
