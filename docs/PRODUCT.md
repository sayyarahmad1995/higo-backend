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

## Driver onboarding

Become a Driver → Driver Details → Vehicle Details → Upload Documents → Review & Submit → Application Pending Review.

The authenticated account reads and saves its draft through GET and PATCH on `/api/v1/me/driver-application`. A draft revision prevents stale saves and uploads from overwriting newer changes. The Driver and Vehicle steps validate the legal name, make, model, year, color, and registration number. Changing saved details clears the corresponding document pair.

POST to `/api/v1/me/driver-application/identity-documents` saves the CNIC pair. POST to `/api/v1/me/driver-application/vehicle-documents` saves the registration and insurance pair. Each upload attaches its encrypted bytes to the same draft revision in one transaction. The API returns only metadata and document presence. Use JPEG or PNG. CNIC images are limited to 1 MiB each and the identity request to 3 MiB. Vehicle images are limited to 2 MiB each and the vehicle request to 6 MiB. Images are limited to 4096 pixels per side and 8 megapixels. Core bounds request intake, time, and image-processing concurrency, normalizes images to remove metadata, and encrypts them with AES-GCM. Configure a protected, stable Base64-encoded 32-byte `HIGO_DRIVER_DOCUMENT_KEY` across restarts.

The final POST to `/api/v1/me/driver-application` validates the complete draft and records the submission time under the same account lock as draft and upload writes. It freezes the exact details and encrypted evidence in one application version and returns `pending_review` while the submission awaits administrative attention. Retrying that revision returns the same submission. Later writes cannot change it. The schema identifies each snapshot by account and application version so a future correction can use a new revision. Submission confers neither membership, approval, nor marketplace eligibility.

The forward migration preserves legacy identity and vehicle rows and their existing cleanup. The legacy routes are removed and no legacy pair is treated as a submitted application. Users start a new wizard so they can confirm the evidence and submit it explicitly. This release allows one application per account. Draft uploads replace the previous pair in place, and cleanup removes draft images after 30 days without activity while retaining saved details. Submitted evidence remains bound to its snapshot, with account deletion cascading to the record. Validate production retention, backup expiry and restore behavior, key rotation and recovery, physical-device picker recovery, and HTTPS ingress before collecting real documents.

Core has no administrative HTTP routes or UI. Review decisions and any future correction workflow belong to later work.
