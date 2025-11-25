# Web3Authn Scripts

This directory contains scripts for managing Web3Authn contract deployments.

First ensure `.env` file is filled out.

To deploy a contract, use:
```
# production
sh deploy.sh

# development
sh deploy-dev.sh
```

Then to upgrade a contract, use:
```
# production
sh upgrade.sh

# development
sh upgrade-dev.sh
```