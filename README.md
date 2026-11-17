# Spore Microfinance

Cloudflare-first customer application and administrator workflow foundation.

## Official architecture
See [ARCHITECTURE.md](./ARCHITECTURE.md) for the system structure, roles, data domains, security boundaries, financial workflow and release model.

## Administrator configuration
See [docs/ADMIN_SETUP.md](./docs/ADMIN_SETUP.md) for the administrator-owned configuration and go-live checklist.

## Stack
- Cloudflare Workers (spore-microfinance)
- Cloudflare D1 (spore-microfinance-db)
- Static assets in public/
- Worker API in src/worker.js
- Ordered D1 migrations in migrations/

## Local development and deployment
1. Install Wrangler in a development environment.
2. Confirm the D1 database ID and bindings in wrangler.toml.
3. Apply migrations to the intended environment.
4. Configure required Worker secrets through Cloudflare; never commit secrets.
5. Run syntax, API, auth, MFA, role-isolation, financial workflow and browser regression tests.
6. Deploy the reviewed commit and verify the deployed version, bindings and live health endpoints.

## Production boundary
This is not a licensed or production-ready lender/core banking system. Do not accept deposits, disburse credit, or process real payments until all applicable licences, approved product terms, security and privacy controls, independent review, and verified payment integrations are in place and tested. A repayment entered by staff is a record, not proof of bank or mobile-money settlement.
