# Locked HiGO Decisions

**Status:** Accepted baseline for the new repository (2026-11-06). These decisions are stable working contracts, not immutable dogma. Change only by recording the reason and updating the relevant authoritative document before implementation.

| Domain | Accepted decision |
| --- | --- |
| Product | Mobility platform, ride-hailing first |
| Backend | Go modular monolith; feature-based internal modules |
| Client | Existing Flutter repository; application-owned backend API |
| Authentication | Native Go phone + password; SMS for registration/recovery only |
| Recovery | Recovery-only authorization; OTP verification must not issue an ordinary app session |
| Sessions | Application-owned, rotating and revocable sessions |
| Database | PostgreSQL, versioned migrations |
| Infrastructure | Lightweight self-managed, container-ready; no speculative microservices |
| Admin | Independent Admin Operations deployment with a Go backend, React 19 + TypeScript + Vite frontend, and dedicated PostgreSQL database. Cross-service operations use explicit, authenticated Admin–Core contracts. |
| Delivery | End-to-end vertical slices driven by actual Flutter user journeys |
| Documentation | This concise current-state handbook is authoritative; old repository is reference only |

## Not adopted

Ory Kratos and Supabase Auth/GoTrue are historical evaluations and **not** chosen providers. Old ADRs or experimental branches must not silently override this repository's contracts.

## Change discipline

When evidence requires change: document the issue, affected contracts, accepted alternative, migration implications, and date. Do not create parallel contradictory 'accepted' decisions.
