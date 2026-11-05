# Native Authentication Contract

## Decision

Implement native phone authentication inside the HiGO Go backend. **No Kratos or GoTrue runtime dependency**. The Flutter app calls only HiGO's HTTP APIs. No external provider API is exposed to the client.

## Required flows

1. **Registration:** E.164 phone number, password, SMS verification challenge, and account creation/activation with verified phone. Prevent duplicate/ambiguous accounts and partial states.
2. **Normal sign-in:** Phone + password. No SMS challenge. Unknown phone and wrong password have identical external failure semantics. No public phone-existence lookup.
3. **Recovery:** Request SMS OTP for an existing phone; avoid disclosing whether it exists. Consume an OTP restricted to the recovery purpose, issue only a short-lived recovery credential, permit password change only, consume the credential and revoke sessions according to policy. Recovery OTP alone must not create a normal authenticated session.
4. **Sessions:** Server-owned opaque, cryptographically random access and refresh tokens (subject to design validation), only token digests in storage, expiration, atomic refresh rotation, logout, and account-wide revocation. Flutter securely stores its credentials.
5. **Current user and authorization:** Authenticated identity mapped to one HiGO account; business capabilities and permissions are separately enforced by each protected route.

## Mandatory security properties

- Use an established Argon2id implementation with unique salts and bounded cost parameters; never store plaintext passwords.
- Generate secrets with a cryptographically secure random source.
- OTP challenges are purpose-bound, short-lived, single-use, attempt-limited, rate-limited, and consumed atomically; test concurrent verification.
- Rate limit login, registration, OTP issuance, and recovery at appropriate dimensions; prevent SMS abuse.
- Use generic external authentication/recovery responses and do not expose secrets in logs or errors.
- Protect sessions from refresh replay and concurrent rotation, and revoke sessions upon security-sensitive changes.
- TLS, configuration validation, safe secret management, audit events, and appropriate API request limits are required before production use.
- Validate both unit and real-PostgreSQL integration behavior; include adversarial tests for enumeration, replay, races, expiry, and cross-account privilege misuse.

## Scope boundary

Initial implementation contains only phone/password/OTP/recovery/session flows. Social login, passkeys, enterprise federation, and speculative identity administration are out of scope.

## Acceptance

Code and tests must demonstrate the exact user journey in the existing Flutter authentication screens. A two-day implementation goal is not a substitute for security review or production approval.
