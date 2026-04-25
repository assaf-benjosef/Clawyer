#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./setup.sh <DISCORD_ID>"
  echo "Example: ./setup.sh 206151060748894208"
  exit 1
fi

DISCORD_ID="$1"

# Automatically find node and openclaw from standard or nvm paths
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.nvm/current/bin:$PATH"

echo "🦀 Building Clawyer..."
npm install >/dev/null 2>&1 || true
npm run build

echo "🦀 Generating OpenClaw config payload..."
BATCH_JSON=$(node scripts/setup.mjs "$DISCORD_ID")

if [ -z "$BATCH_JSON" ]; then
    echo "❌ Failed to generate configuration batch."
    exit 1
fi

echo "🦀 Applying config to OpenClaw..."
openclaw config set --batch-json "$BATCH_JSON" --strict-json

echo "🦀 Restarting Gateway to apply boundary changes..."
openclaw gateway restart --wait 2>/dev/null || true

echo "✅ Setup complete! Clawyer is active."
echo "Try running 'rmdir /tmp/foobar' via your Discord agent to test the interactive approval workflow."
