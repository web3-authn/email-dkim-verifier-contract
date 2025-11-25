default:
    @echo "Available commands:"
    @echo "  just deploy      - Deploy contract to production"
    @echo "  just deploy-dev  - Deploy contract to development"
    @echo "  just upgrade     - Upgrade contract in production"
    @echo "  just upgrade-dev - Upgrade contract in development"
    @echo "  just request     - Call request_email_verification with sample DKIM email"
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
    ./scripts/request_email_verification.sh
