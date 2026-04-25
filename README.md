# 🦞 Clawyer for OpenClaw

**Clawyer** is a Zero-Trust "Justify-Then-Execute" security guardrail plugin for OpenClaw. It forces autonomous AI agents to explicitly argue and justify their intent before executing potentially dangerous terminal commands.

## How it Works

Clawyer intercepts terminal tool calls (`exec`) before they hit your system. If the command matches a dangerous pattern (like `rm`, `mv`, `curl`, etc.), Clawyer completely halts execution and demands a cryptographic justification. 

Instead of showing you an ambiguous "Approve `rmdir /tmp/test-data`?" prompt, you get an explicit, context-rich notification where the agent says: **"I am doing X, and here is exactly why I need to do it."**

1. **Agent attempts a dangerous command.**
2. **Clawyer blocks it.** The agent is instructed to use the `clawyer_justify` tool.
3. **Agent justifies its intent.** The parameters and justification are cryptographically bound via FNV-1a hashing.
4. **Agent retries the command.** Clawyer verifies the hash matches the stored justification to prevent "bait-and-switch" attacks.
5. **Human-in-the-Loop Approval.** The justification is pushed natively into the Human's chat UI (Discord, Slack, etc.) for absolute transparency.

## Installation

Clawyer manages sensitive API boundaries. Because OpenClaw prevents plugins from automatically granting themselves UI interactions or modifying your agent's allow-list, you must explicitly install Clawyer by authorizing it.

To install Clawyer and configure it around your OpenClaw session, run the automated script:

```bash
# Clone the repository
git clone <your-repo-url>
cd clawyer

# Run the installer
./setup.sh <YOUR_DISCORD_USER_ID>
```

This will safely compile the TypeScript bindings and construct a native config payload to safely inject the permissions into your OpenClaw JSON array.

## Configuration & Policies

Clawyer's policies are deeply integrated into OpenClaw's native configuration engine via our plugin manifest. You don't need to edit the source code to change what commands are considered "dangerous" or which tools to block outright.

You can natively override the heuristic matching rules using `openclaw config`:

```bash
# Example: Adding specific dangerous commands to the policy
openclaw config set plugins.clawyer.policies '{
  "default": "allow",
  "rules": [
    {
      "tools": ["exec"],
      "mode": "human_approval",
      "dangerousCommands": ["\\brm\\b", "\\bcurl\\b", "\\bsudo\\b", "\\bdocker rmi\\b"]
    }
  ]
}' --strict-json
```

## Roadmap 🚀

- **Phase 1 (MVP)**: Heuristic regex matching, FNV-1a anti-cheat binding, and native UI fallback. *(Completed)*
- **Phase 2 (LLM Judge)**: Coming soon! We will introduce a background Judge LLM to semantically evaluate the agent's justification against an intent-based heuristic list, rejecting lazy or hallucinatory justifications before they ever reach the human operator.
