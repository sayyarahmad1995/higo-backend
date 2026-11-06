# Native authentication

Flutter calls the Go API. PostgreSQL owns verified accounts, purpose-bound challenges, password credentials, recovery grants, and sessions.

On the welcome screen, Get Started opens registration and Log In opens password sign-in. This replaces the prototype's simulated account lookup. Registration collects name, optional email, and password before sending a verification code. A verified registration returns a session. Forgot Password requests and verifies a recovery code, then accepts a new password and returns to the login screen. No public lookup reveals whether a phone is registered.

## HTTP API

All paths below begin with `/api/v1`. POST requests with a body use JSON. Passwords are used as entered, with a 12–128 UTF-8 byte limit. The server requires an international number and validates it against numbering-plan metadata before storage.

| Method and path | Input | Success |
| --- | --- | --- |
| POST /auth/register | `phone`, `password`, `name`, optional `email` | 202 with `challenge`, `expires_in`, `resend_after` |
| POST /auth/register/verify | `challenge`, six-digit `code` | 201 with session tokens |
| POST /auth/login | `phone`, `password` | 200 with session tokens |
| POST /auth/recovery/request | `phone` | 202 with the same challenge shape for known and unknown phones |
| POST /auth/recovery/verify | `challenge`, six-digit `code` | 200 with `recovery_token` and `expires_in` |
| POST /auth/recovery/reset | `recovery_token`, new `password` | 204 |
| POST /auth/refresh | `refresh_token` | 200 with replacement session tokens |
| POST /auth/logout | Access bearer | 204 |
| GET /me | Access bearer | 200 with `id`, `phone`, `name`, `email`, `capabilities` |
| PATCH /me | Access bearer and `name`, `email`, or both | 200 with the updated `/me` response |

Session responses include `access_token`, `refresh_token`, and `expires_in` in seconds. Errors are JSON with an `error` code. Invalid and expired verification proofs return 400. Unknown phones and incorrect passwords return 401 with `invalid_credentials`. Invalid, expired, or revoked session tokens return 401. Throttling returns 429. A saturated password worker returns 503.

Profile updates apply only to the account identified by the access token. Omitted or `null` fields stay unchanged, and at least one string field is required. The API trims surrounding whitespace, accepts names up to 150 UTF-8 bytes and email addresses up to 254 bytes, and clears email when sent an empty string. Other fields are rejected. Changing a verified phone requires a separate verification flow. Flutter loads the profile through `/me` at sign-in and session restoration and displays the server response after an edit.

## Security behavior

- An accepted issuance request returns 202 before SMS delivery. Repeat the original issuance request to resend after 60 seconds. Each issuance has its own challenge and code. Challenges expire in five minutes and allow five guesses. Only a challenge acknowledged by the SMS gateway can be verified. A failed send or process restart before acknowledgment requires a new issuance. Duplicate registration and unknown-phone recovery return an unusable challenge without sending SMS.
- Challenges store keyed OTP digests. PostgreSQL consumes an OTP in the same transaction as account creation or recovery grant issuance. Registration creates the account only after successful verification. A unique phone constraint handles concurrent registration.
- Argon2id uses a unique random salt, bounded encoded parameters, and configurable memory and passes. The default is 64 MiB and three passes. Unknown accounts use a dummy hash. Two concurrent hash operations are allowed per process.
- Recovery credentials last ten minutes and authorize password reset only. Password reset consumes the credential, increments the password version, and revokes all sessions in one transaction. Older recovery grants and challenges cannot reset the changed password.
- Access tokens expire after 15 minutes or at session expiry, whichever is earlier. Refresh sessions expire after 30 days from issuance. Rotation replaces access and refresh credentials atomically. Reuse of a consumed refresh token revokes that session. A client that loses a refresh response may need to sign in again.
- Mobile keeps access tokens in memory and the refresh token in platform secure storage. It restores a session by refreshing and loading the current user. Concurrent refresh attempts are coalesced.
- PostgreSQL limits requests by source peer and route. Login is capped at ten attempts per phone per 15-minute window. SMS issuance is capped at ten requests per peer and route per minute, five issuances per phone and purpose per hour, and 60 issuances per minute across the deployment. A rolling 60-second per-phone cooldown spans both SMS purposes. Cooldown rejections preserve the hourly budget. Each instance dispatches SMS independently with a bounded pool. Real and suppressed sends reserve capacity for the same interval. Exhausted capacity returns 503.
- Every verified account has Rider membership. PostgreSQL stores optional Driver membership, which `/me` reports for the same account and session. Membership is provisioned through trusted database access and has no public write endpoint. Flutter offers Driver mode only for accounts with Driver membership. This membership is separate from onboarding approval and marketplace eligibility, which require their own server checks when those operations are introduced.
- Logs contain operation and outcome codes without authentication secrets. The explicit loopback-only development SMS adapter prints codes to the local console.

## Deployment and review

Development acceptance covers integrated behavior, review, and green CI. Before enabling authentication for production users, complete these release checks:

- Verify refresh persistence across a physical Android device restart and reauthentication after a lost refresh response.
- Verify live Twilio delivery and provider failure behavior with the intended sender and destinations.
- Validate the deployed containers, private backend listener, HTTPS ingress, and mobile connectivity. Configure PostgreSQL TLS when traffic leaves the host.
- Measure enumeration signals and resource exhaustion under load. The app rate-limits by the immediate TCP peer, so validate proxy client-IP limits and the combined budget.
- Complete an independent security review and production approval.
