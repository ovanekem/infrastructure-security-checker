#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed."
    echo "Please install Node.js version 20 or higher."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo "Error: Node.js version 20 or higher is required."
    echo "Current version: $(node -v)"
    echo "Please run: nvm use 20"
    exit 1
fi

cd "$SCRIPT_DIR" || exit 1

if [ ! -d "node_modules" ] || [ ! -x "node_modules/.bin/tsc" ]; then
    echo "Installing project dependencies..."
    if [ -f "package-lock.json" ]; then
        npm ci --no-audit --no-fund || exit 1
    else
        npm install --no-audit --no-fund || exit 1
    fi
fi

if [ ! -f "dist/cli/main.js" ]; then
    npm run build || exit 1
fi

node dist/cli/main.js "$@"
