# Spore Microfinance

Cloudflare-first digital finance platform foundation.

## Current scope
- Responsive customer portal
- Loan and account enquiry intake
- Loan repayment estimator
- Cloudflare Workers API and D1 schema

## Cloudflare setup
1. Install Wrangler: `npm install -D wrangler`.
2. Create D1: `npx wrangler d1 create spore-microfinance-db`.
3. Add the returned database ID to `wrangler.toml`.
4. Apply migrations: `npx wrangler d1 migrations apply spore-microfinance-db --remote`.
5. Deploy: `npx wrangler deploy`.

This is a development foundation, not a licensed or production-ready lender. Do not collect deposits, disburse credit or process real payments until applicable licences, approved product terms, secure authentication, audit controls, privacy safeguards and verified payment integrations are in place and tested.
