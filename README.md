# HiGO Backend

Go backend for **HiGO**, a mobility platform launching with ride-hailing.

## Status

New repository, fresh history. Backend implementation has not begun. The first vertical slice is native phone authentication, built against the existing Flutter client. Do not treat project documentation as evidence that features are implemented.

## Source of truth

Read these before implementing a slice:

- [Architecture](docs/ARCHITECTURE.md): current technical rules and delivery boundaries.
- [Product](docs/PRODUCT.md): ride-hailing scope and vertical-slice sequence.
- [Authentication](docs/AUTHENTICATION.md): native phone-authentication contract.
- [Decisions](docs/DECISIONS.md): accepted architectural decisions.

Keep these documents short, consistent, and up to date. A deliberate change requires an explicit decision and corresponding implementation updates.

## Repositories

- Active Flutter client: [uber-clone-mobile](https://github.com/sayyarahmad1995/uber-clone-mobile).
- Historical Go backend reference: [uber-clone](https://github.com/sayyarahmad1995/uber-clone). Do not merge or copy its authentication architecture wholesale.

## Implementation principles

- Go modular monolith and PostgreSQL.
- One end-to-end Flutter user journey per vertical slice.
- Keep application-owned APIs as the only client authentication interface.
- Reuse established security libraries, not homemade cryptographic primitives.
- Implement required tests and security controls within the same slice.
- No premature microservices, Redis dependency, or enterprise scaffolding.

## Initial slice

Registration, phone OTP verification, phone/password login, phone-only password recovery, refreshable sessions, logout and authorization middleware. Validate with the actual Flutter screens and real PostgreSQL integration tests before moving on.
