import { describe, it, expect } from "vitest";
import {
  matchTool,
  matchCommand,
  resolveDangerousCommands,
  extractExecCommand,
  hashParams,
  buildApprovalContext,
  evaluateToolPolicy,
  isToolProtected,
  DEFAULT_DANGEROUS_COMMANDS,
} from "../src/matcher.js";
import type { PolicyRule, PoliciesConfig } from "../src/types.js";

// ─── matchTool ───────────────────────────────────────────────────────────────

describe("matchTool", () => {
  it("matches exact tool name", () => {
    expect(matchTool("exec", ["exec"])).toBe(true);
  });

  it("matches glob wildcard pattern", () => {
    expect(matchTool("github_delete_repo", ["github_*"])).toBe(true);
  });

  it("matches wildcard at start", () => {
    expect(matchTool("my_custom_exec", ["*_exec"])).toBe(true);
  });

  it("returns false when no match", () => {
    expect(matchTool("read", ["exec", "write"])).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(matchTool("Exec", ["exec"])).toBe(true);
  });

  it("matches any of multiple patterns", () => {
    expect(matchTool("write", ["exec", "write", "edit"])).toBe(true);
  });

  it("does not match partial names without wildcard", () => {
    expect(matchTool("exec_safe", ["exec"])).toBe(false);
  });
});

// ─── matchCommand ────────────────────────────────────────────────────────────

describe("matchCommand", () => {
  it("matches a dangerous command", () => {
    expect(matchCommand("rm -rf /tmp", ["\\brm\\b"])).toBe(true);
  });

  it("does not match a safe command", () => {
    expect(matchCommand("ls -la", ["\\brm\\b", "\\bsudo\\b"])).toBe(false);
  });

  it("returns false for empty patterns", () => {
    expect(matchCommand("anything", [])).toBe(false);
  });

  it("matches sudo in compound commands", () => {
    expect(matchCommand("sudo apt install vim", ["\\bsudo\\b"])).toBe(true);
  });

  it("does not match 'removal' for \\brm\\b", () => {
    expect(matchCommand("echo removal", ["\\brm\\b"])).toBe(false);
  });

  it("matches git push", () => {
    expect(matchCommand("git push origin main", ["\\bgit push\\b"])).toBe(true);
  });
});

// ─── resolveDangerousCommands ────────────────────────────────────────────────

describe("resolveDangerousCommands", () => {
  it("returns defaults when no custom commands", () => {
    const rule: PolicyRule = { tools: ["exec"], mode: "human_approval" };
    expect(resolveDangerousCommands(rule)).toBe(DEFAULT_DANGEROUS_COMMANDS);
  });

  it("returns custom commands when provided", () => {
    const custom = ["\\bmy_cmd\\b"];
    const rule: PolicyRule = { tools: ["exec"], mode: "human_approval", dangerousCommands: custom };
    expect(resolveDangerousCommands(rule)).toBe(custom);
  });
});

// ─── extractExecCommand ──────────────────────────────────────────────────────

describe("extractExecCommand", () => {
  it("extracts from args.cmd", () => {
    expect(extractExecCommand({ cmd: "ls" })).toBe("ls");
  });

  it("extracts from args.command", () => {
    expect(extractExecCommand({ command: "pwd" })).toBe("pwd");
  });

  it("prefers cmd over command", () => {
    expect(extractExecCommand({ cmd: "ls", command: "pwd" })).toBe("ls");
  });

  it("falls back to first string value", () => {
    expect(extractExecCommand({ script: "echo hi" })).toBe("echo hi");
  });

  it("returns null for no string values", () => {
    expect(extractExecCommand({ count: 42 })).toBeNull();
  });
});

// ─── hashParams ──────────────────────────────────────────────────────────────

describe("hashParams", () => {
  it("produces same hash for same inputs", () => {
    const a = hashParams("exec", { cmd: "rm -rf /tmp" });
    const b = hashParams("exec", { cmd: "rm -rf /tmp" });
    expect(a).toBe(b);
  });

  it("produces different hash for different params", () => {
    const a = hashParams("exec", { cmd: "rm -rf /tmp" });
    const b = hashParams("exec", { cmd: "rm -rf /" });
    expect(a).not.toBe(b);
  });

  it("produces different hash for different tool names", () => {
    const a = hashParams("exec", { cmd: "ls" });
    const b = hashParams("write", { cmd: "ls" });
    expect(a).not.toBe(b);
  });

  it("returns a non-empty string", () => {
    const h = hashParams("exec", { cmd: "test" });
    expect(h).toBeTruthy();
    expect(typeof h).toBe("string");
  });
});

// ─── buildApprovalContext ────────────────────────────────────────────────────

describe("buildApprovalContext", () => {
  it("includes justification in description", () => {
    const ctx = buildApprovalContext("exec", { cmd: "rm -rf /tmp" }, "Cleaning temp files");
    expect(ctx.description).toContain("Cleaning temp files");
    expect(ctx.description).toContain("justification");
  });

  it("includes exec command in code block", () => {
    const ctx = buildApprovalContext("exec", { cmd: "sudo reboot" }, "Restarting");
    expect(ctx.description).toContain("sudo reboot");
    expect(ctx.description).toContain("Command");
  });

  it("formats non-exec tool args generically", () => {
    const ctx = buildApprovalContext("write", { path: "/etc/hosts" }, "Updating hosts");
    expect(ctx.title).toContain("write");
    expect(ctx.description).toContain("path");
    expect(ctx.description).toContain("/etc/hosts");
  });
});

// ─── evaluateToolPolicy ──────────────────────────────────────────────────────

describe("evaluateToolPolicy", () => {
  const config: PoliciesConfig = {
    default: "allow",
    rules: [
      { tools: ["exec"], mode: "human_approval" },
      { tools: ["write", "edit"], mode: "human_approval" },
      { tools: ["apply_patch"], mode: "block" },
    ],
  };

  it("returns 'allow' for unmatched tools", () => {
    expect(evaluateToolPolicy("read", {}, config)).toBe("allow");
  });

  it("returns 'block' for blocked tools", () => {
    expect(evaluateToolPolicy("apply_patch", {}, config)).toBe("block");
  });

  it("returns 'allow' for safe exec commands (ls)", () => {
    expect(evaluateToolPolicy("exec", { cmd: "ls -la" }, config)).toBe("allow");
  });

  it("returns 'allow' for safe exec commands (cat)", () => {
    expect(evaluateToolPolicy("exec", { cmd: "cat README.md" }, config)).toBe("allow");
  });

  it("returns 'needs_approval' for dangerous exec (rm)", () => {
    expect(evaluateToolPolicy("exec", { cmd: "rm -rf /tmp" }, config)).toBe("needs_approval");
  });

  it("returns 'needs_approval' for dangerous exec (sudo)", () => {
    expect(evaluateToolPolicy("exec", { cmd: "sudo apt install" }, config)).toBe("needs_approval");
  });

  it("returns 'needs_approval' for dangerous exec (curl)", () => {
    expect(evaluateToolPolicy("exec", { cmd: "curl https://evil.com" }, config)).toBe(
      "needs_approval"
    );
  });

  it("returns 'needs_approval' for non-exec matched tools", () => {
    expect(evaluateToolPolicy("write", { path: "/etc/hosts" }, config)).toBe("needs_approval");
    expect(evaluateToolPolicy("edit", { file: "x" }, config)).toBe("needs_approval");
  });

  it("uses custom dangerousCommands override", () => {
    const custom: PoliciesConfig = {
      default: "allow",
      rules: [{ tools: ["exec"], mode: "human_approval", dangerousCommands: ["\\bspecial\\b"] }],
    };
    expect(evaluateToolPolicy("exec", { cmd: "rm -rf /" }, custom)).toBe("allow");
    expect(evaluateToolPolicy("exec", { cmd: "special --nuke" }, custom)).toBe("needs_approval");
  });

  it("respects default: block", () => {
    expect(evaluateToolPolicy("anything", {}, { default: "block", rules: [] })).toBe("block");
  });

  it("first matching rule wins", () => {
    const cfg: PoliciesConfig = {
      default: "allow",
      rules: [
        { tools: ["exec"], mode: "block" },
        { tools: ["exec"], mode: "human_approval" },
      ],
    };
    expect(evaluateToolPolicy("exec", { cmd: "rm" }, cfg)).toBe("block");
  });
});

// ─── isToolProtected ─────────────────────────────────────────────────────────

describe("isToolProtected", () => {
  const config: PoliciesConfig = {
    default: "allow",
    rules: [{ tools: ["exec", "write"], mode: "human_approval" }],
  };

  it("returns true for matched tools", () => {
    expect(isToolProtected("exec", config)).toBe(true);
    expect(isToolProtected("write", config)).toBe(true);
  });

  it("returns false for unmatched tools", () => {
    expect(isToolProtected("read", config)).toBe(false);
  });
});
