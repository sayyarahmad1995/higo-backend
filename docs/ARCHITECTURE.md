# HiGO Backend Architecture

## Authority

This document defines the current backend architecture. [PRODUCT.md](PRODUCT.md), [AUTHENTICATION.md](AUTHENTICATION.md), and [DECISIONS.md](DECISIONS.md) provide the remaining contracts. Do not revive superseded designs without explicitly amending these documents.

## System boundaries

- **Flutter client:** Existing separate repository, Android first. UI screens initiate user journeys; they are not authoritative for security, permission checks, transactional invariants, or server-owned state.
- **Backend:** One Go modular monolith exposing application-owned HTTP APIs. Group implementation by business feature, not giant global controller/service/repository layers.
- **Database:** PostgreSQL is the transactional source of truth, with versioned, forward-only migrations. Do not reset or overwrite databases as part of routine startup.
- **Administration:** Framework-free HTML/CSS/vanilla JavaScript SPA, with a persistent sidebar and Go APIs. Build operational features only when required by a vertical slice.
- **Infrastructure:** Container-ready, self-managed deployment. Avoid microservices and Redis until a measurable requirement justifies them.

## Engineering contract

1. Inspect the relevant Flutter screens and transitions before designing an endpoint.
2. Document request/response contracts, state transitions, authorization rules, and failure modes for the vertical slice.
3. Implement Go handlers, domain logic, storage, migrations, and tests together.
4. Integrate and test actual Flutter flows; validate concurrent operations and failure paths.
5. Keep modules simple and compatible; add abstractions only when real reuse or isolation requires them.
6. No hard-coded operational business configuration when an admin-owned setting is needed (including named-place snapping distance).
7. Never claim production readiness solely because tests pass; production release requires appropriate security and operational review.

## Initial module roadmap

Native authentication → account/capabilities → Driver onboarding/vehicles → Rider ride requests → Driver offers/bidding → trip lifecycle → cash settlement/receipts → relevant Admin Operations.

Shared functionality is introduced by the first slice that needs it, not by speculative up-front architecture.
