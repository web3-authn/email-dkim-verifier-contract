default:
    @echo "Available commands:"
    @echo "  just deploy      - Deploy contract to production"
    @echo "  just deploy-dev  - Deploy contract to development"
    @echo "  just upgrade     - Upgrade contract in production"
    @echo "  just upgrade-dev - Upgrade contract in development"
    @echo "  just request     - Call request_email_verification with sample DKIM email"
    @echo "  just set-outlayer-keys - Refresh worker public key in contract"
    @echo "  just set-outlayer-wasm - Set worker wasm URL + hash in contract (defaults to latest.json)"
    @echo "  just vite-dev    - Run Vite example app"
    @echo ""
    @echo "Make sure to set up your .env file before running any commands."

# Deploy the contract to production (reproducible WASM)
deploy:
    @echo "Deploying contract to production..."
    sh ./scripts/deploy.sh

# Deploy the contract to development (non-reproducible WASM, faster builds)
deploy-dev:
    @echo "Deploying contract to development..."
    sh ./scripts/deploy-dev.sh

# Upgrade the contract in production (reproducible WASM)
upgrade:
    @echo "Upgrading contract in production..."
    sh ./scripts/upgrade.sh

# Upgrade the contract in development (non-reproducible WASM, faster builds)
upgrade-dev:
    @echo "Upgrading contract in development..."
    sh ./scripts/upgrade-dev.sh

# Call request_email_verification with a sample DKIM email
request:
    @echo "Calling request_email_verification on contract..."
    sh ./scripts/request_email_verification.sh

set-outlayer-keys:
    @echo "Setting Outlayer worker + contract keys..."
    sh ./scripts/set_outlayer_keys.sh

set-outlayer-wasm:
    @echo "Setting Outlayer worker wasm source..."
    sh ./scripts/set_outlayer_worker_wasm_from_r2_object.sh

test:
    @echo "cd email-dkim-verifier-contract && cargo test --features unit-testing"
    sh ./scripts/tests.sh
    @echo "cargo test"
    cargo test

vite-dev:
    cd examples/vite && pnpm run dev
