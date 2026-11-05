# HiGO Product Contract

HiGO is a mobility platform. **Ride-hailing is its first product**; courier, freight, and other categories are deferred.

## MVP principles

- One user account can have Rider and Driver capabilities; do not implement separate unrelated identity systems for each.
- Rider is the default capability.
- Driver access to the marketplace depends on approved identity, vehicle, and service eligibility.
- A Rider selects pickup, destination, service where applicable, and proposes a fare.
- Eligible Drivers may accept the proposed fare or submit a counteroffer. The Rider selects the winning offer; the server enforces atomic assignment and availability.
- Trip state, ownership, cancellation, completion, and financial records are authoritative on the backend.
- Initial settlement is cash-based; expand payment features only when a slice requires them.

## Development model

The active Flutter repository defines existing screens, user journeys, and presentation states, but UI code alone is not a complete backend specification. Review the old backend for proven business rules where needed; make any missing rule explicit before implementing it.

Implement vertical slices: authentication; account/capabilities; Driver onboarding and vehicles; Rider booking; Driver offers; trips; settlement/receipts; necessary operational tooling.

A slice is complete when Go APIs, PostgreSQL persistence, Flutter integration, and critical success/error/concurrency tests are verified together.
