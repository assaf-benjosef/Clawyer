import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function main() {
    const discordId = process.argv[2];
    if (!discordId) {
        console.error("Missing Discord ID parameter.");
        process.exit(1);
    }
    
    // Read current config to do safe appends
    const configPath = path.join(os.homedir(), '.openclaw', 'openclaw.json');
    let config = {};
    try {
        config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {
        // Assume empty if failed
    }
    
    // Safety check existing arrays
    const currentTools = (config.tools && config.tools.alsoAllow) || [];
    const alsoAllow = Array.from(new Set([...currentTools, "clawyer_justify"]));
    
    const currentApprovers = (config.channels && config.channels.discord && config.channels.discord.execApprovals && config.channels.discord.execApprovals.approvers) || [];
    const approvers = Array.from(new Set([...currentApprovers, discordId]));

    // Construct batch operations for OpenClaw native config mechanism
    const batch = [
        { path: "tools.alsoAllow", value: alsoAllow },
        { path: "approvals.plugin", value: { enabled: true, mode: "session" } },
        { path: "channels.discord.execApprovals", value: { enabled: true, approvers } },
        { path: "channels.discord.agentComponents", value: { enabled: true } }
    ];

    // Output strictly JSON so our bash script can pipe it
    console.log(JSON.stringify(batch));
}
main();
