# SPORE Microfinance — Official Platform Architecture

**Status:** controlled application and administration foundation; not authorization to accept deposits, disburse credit, or process customer payments.

## 1. Architecture overview

```text
Customers / authorised administrator
                 |
              HTTPS
                 |
       Cloudflare Workers edge
                 |
        spore-microfinance
        /                 \
  Static assets          JSON API
  public/                /api/*
                            |
                       D1 binding
                            |
                 spore-microfinance-db
```

- **Presentation:** responsive public website, customer portal, administrator dashboard and installable PWA assets in public/.
- **Application/API:** src/worker.js handles authentication, customer records, KYC submissions, loan applications, administrator actions, repayment schedules, receipts, settings and verification endpoints.
- **Persistence:** Cloudflare D1; ordered SQL migrations live in migrations/.
- **Hosting:** Cloudflare Worker named spore-microfinance; static assets use the ASSETS binding.
- **Source control:** GitHub repository SPOREADVENTURESLIMITED/spore-microfinance, default branch main.

## 2. Request routing

Static pages and assets are served from public/. API requests under /api/* must execute the Worker before static-asset fallback. Wrangler config therefore uses selective assets.run_worker_first = ["/api/*"]; SPA fallback must never turn an API miss into an HTML page.

The Worker returns JSON for API routes and delegates non-API requests to ASSETS.fetch(request). Unknown API paths return JSON 404.

## 3. Roles and journeys

### Public visitor
1. Views public services, eligibility notices, contact details and disclosures.
2. Opens the customer portal.
3. Can submit a general enquiry without being treated as an approved borrower.

### Customer
1. Registers with a phone number and password.
2. Signs in using a secure session cookie.
3. Completes the KYC profile (currently details and document suffix only; document inspection is a controlled manual process).
4. Submits a loan application.
5. Views own applications, approved schedules, recorded repayments and verification documents.
6. Uses account recovery only after the administrator configures the SMS provider and reset-code pepper.

Customer data is scoped to the authenticated customer ID. The customer portal must never expose another customer's KYC, loan, schedule or payment records.

### Administrator
1. First administrator activation is a one-time bootstrap protected by Cloudflare Worker secrets and the configured administrator phone.
2. The administrator signs in and must enrol an authenticator (TOTP) before accessing protected operations.
3. One-time recovery codes are shown at creation/regeneration and must be stored offline by the administrator.
4. The administrator reviews KYC, loan applications and records repayments.
5. The administrator configures organisation identity, contacts, branding, approved loan terms and later provider settings.
6. Administrator operations are audit logged.

The first-administrator bootstrap is not a public registration feature. Never expose or paste bootstrap secrets into source control, logs, tickets or chat.

## 4. Data domains

| Domain | Main records | Purpose |
|---|---|---|
| Identity and access | customers, sessions, login_attempts | Customer/admin identity, password hashes, sessions and throttling |
| Administrator MFA | admin_mfa_recovery_codes, MFA columns on customers and sessions | TOTP and one-time recovery |
| Customer due diligence | kyc_profiles | Identity details and review status |
| Credit workflow | loan_applications, loan_terms, repayment_schedule | Application, approval terms and scheduled instalments |
| Collections | repayments, repayment_allocations, payment_assertions | Staff-recorded payments and schedule allocation |
| Governance | audit_logs, site_settings, enquiries | Audit trail, editable organisation details and enquiries |
| Account recovery | password_resets | Time-limited reset challenges |

All schema changes must be delivered as ordered SQL migrations. Never make undocumented production schema edits.

## 5. Security boundaries

- Passwords are stored as PBKDF2-SHA256 hashes with per-account random salts.
- Session tokens are random, stored as SHA-256 digests, and issued in Secure, HttpOnly, SameSite=Strict cookies.
- Administrator endpoints require an authenticated administrator session and completed MFA.
- Bootstrap token and phone restrictions are Worker secrets, not public variables.
- TOTP recovery codes are stored as hashes and are one-time use.
- Customer data endpoints require a session and bind database queries to the current customer.
- SQL values are parameter-bound.
- Financial writes use D1 batch transactions and payment-version assertions to reduce concurrent double-posting risk.
- API errors returned to clients are generic; server logs must not contain passwords, session tokens, MFA secrets, recovery codes, reset codes or identity-document numbers.
- Static responses receive browser security headers; API responses use Cache-Control: no-store.

## 6. Financial workflow controls

1. Customer submits application.
2. Administrator reviews identity and affordability evidence.
3. KYC must be marked verified before loan approval.
4. Administrator must explicitly enter the approved monthly rate; no silent interest-rate default is permitted.
5. System creates the contractual schedule from the approved principal, term, rate and dates.
6. Administrator records a received payment with reference and note.
7. System allocates payment to outstanding schedule components and audits the event.
8. Customer can view only their own recorded financial documents.

**Important limitation:** a staff-recorded repayment is not a bank/mobile-money confirmation. Payment gateway reconciliation, disbursement, automated collection, savings ledgers, GL/accounting, reversals, refunds and maker-checker approval are not yet implemented as live integrations.

## 7. Administrator-managed configuration

The administrator is responsible for supplying and approving:
- Legal entity name, registration and licence details, jurisdiction, office address and official contact channels.
- Public website name, tagline, logo and support contacts.
- Product availability, eligibility, affordability rules, fees, rates, penalty policy, repayment rules and customer disclosures.
- Approved lending and KYC policies, retention periods and complaint/escalation contacts.
- SMS provider credentials and reset-code pepper, when an approved provider is selected.
- Payment-provider credentials, webhook verification and settlement/reconciliation process, after a formal integration review.
- Authorised staff identities, role assignments and separation-of-duties policy.

Do not insert fabricated legal details, terms, provider credentials or administrator identity.

## 8. Environments and release process

- Keep production D1 separate from any future staging/test database.
- Review source changes and migrations before release.
- Run syntax, API contract, authentication, role-isolation, MFA, KYC, loan schedule, concurrent repayment and browser regression tests.
- Apply migrations to the intended database before deploying code that depends on them.
- Deploy from the reviewed main commit; confirm the deployed Worker version and bindings after deployment.
- Run public health, database readiness, static asset, customer sign-in, administrator MFA and API authorization checks after deployment.
- Keep a rollback path and database backup/restore procedure.

## 9. Current operational boundary

The current release is an application-management foundation. It is not a licensed core banking system and must not be represented as one. Real customer funds, deposit-taking, lending disbursement, payment processing and regulated financial activity remain disabled until licensing, product governance, security review, provider integration and controlled live testing are completed.
