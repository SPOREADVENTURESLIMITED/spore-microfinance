# Administrator Configuration and Go-Live Checklist

This checklist is intended for completion by the authorised administrator after platform engineering work.

## A. Organisation identity
- [ ] Legal entity name and registration details
- [ ] Applicable financial-services licence and permitted activities
- [ ] Jurisdiction, physical office address and official contacts
- [ ] Approved website name, tagline, logo, support phone and email
- [ ] Privacy notice, terms of use, complaints process and retention schedule

## B. Administrator access
- [ ] Confirm control of the bootstrap phone configured in Cloudflare
- [ ] Register the approved administrator account and complete one-time bootstrap
- [ ] Sign in and enrol TOTP in an authenticator app
- [ ] Store one-time recovery codes offline; test one recovery code
- [ ] Confirm administrator MFA is required on every new login
- [ ] Set a unique high-entropy password and enable device security
- [ ] Document emergency access and administrator succession

Never send the bootstrap token, password, TOTP secret, recovery codes or reset codes to another person.

## C. Product and lending policy
- [ ] Define products and customer eligibility
- [ ] Approve rate basis, fees, penalties, term limits and rounding policy
- [ ] Approve affordability and responsible-lending checks
- [ ] Approve KYC evidence and manual review procedure
- [ ] Approve disbursement controls, repayment allocation, arrears and write-off policies
- [ ] Publish customer disclosures before accepting applications

The dashboard requires an administrator to enter the approved monthly interest rate when approving a loan. Do not approve a loan until the full written offer has been authorised and checked.

## D. Provider integrations
- [ ] Choose and contract an SMS provider
- [ ] Set RESET_CODE_PEPPER and provider secrets in Cloudflare Worker secrets
- [ ] Test SMS delivery, expiry, rate limiting and reset flow
- [ ] Select payment provider only after legal and commercial approval
- [ ] Implement and test signed webhook verification, idempotency, reconciliation and refunds before accepting payments

Do not use manual database edits to simulate a payment or disbursement.

## E. Operational controls
- [ ] Create a separate staging database and test environment
- [ ] Approve role matrix and maker-checker rules
- [ ] Establish daily audit and reconciliation review
- [ ] Configure backups, restore tests, retention and incident response
- [ ] Complete privacy and independent security review
- [ ] Complete authorised end-to-end test with synthetic records
- [ ] Sign off release and customer communications

## Go-live restriction

Until all applicable legal, product, security, provider and operational checks are signed off, use the platform only for controlled testing and application intake. Do not accept deposits, disburse loans or claim that a payment has been received solely because an administrator entered a record.
