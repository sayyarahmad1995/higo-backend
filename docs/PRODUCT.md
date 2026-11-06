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

## Driver identity submission

An authenticated Rider can start onboarding from Become a Driver. An account with Driver membership can open the same flow from the Driver account. The form starts with the account name and asks for the legal name and front and back images of the CNIC. Vehicle documents belong to vehicle registration.

GET /api/v1/me/driver-submission returns the account's latest identity submission metadata, or not_submitted. POST accepts legal_name, cnic_front, and cnic_back as JSON, with the images encoded as Base64. Each successful submission creates an immutable version with submitted status. Submission leaves Driver membership, approval, and marketplace eligibility separate.

Uploads accept JPEG or PNG up to 1 MiB per side. The API bounds image dimensions, decodes and re-encodes the images to remove metadata, and encrypts the document bytes with AES-GCM before saving to PostgreSQL. The public API returns metadata only. Set HIGO_DRIVER_DOCUMENT_KEY to a separate Base64-encoded random 32-byte key to enable uploads. Keep the key outside PostgreSQL and protect its backup. Before production collection, validate key management, retention and deletion policy, access auditing, and the intended upload path through HTTPS ingress.

The server caps the complete JSON body at 3 MiB, limits each original and normalized image to 1 MiB, and allows up to 4096 pixels per side and 8 megapixels. It bounds simultaneous upload bodies and image processing separately. Flutter attempts to reduce large images before upload while keeping the original when recompression would increase size. Filenames and client MIME declarations do not determine acceptance.

Incomplete drafts stay on the device in memory. Cleanup removes the encrypted image bytes of superseded versions older than 30 days while keeping version metadata. Each account is capped at 20 versions with document bytes and 250 versions overall. Account deletion cascades to the stored submissions. Before collecting real CNICs, confirm retention and deletion obligations, including backups, and test physical-device picker cancellation and recovery. If both bounded Android picker workers become permanently stalled, users may need to restart the activity. Establish key identifiers, rotation and recovery procedures, and a tested protected key backup before production.

Future document endpoints must apply bounded request bodies, per-file byte and image limits, bounded processing, and cleanup. The initial ceiling is 2 MiB per driver's license or vehicle document image. PDFs require a separate format decision and a maximum of 5 MiB if introduced.

## Vehicle registration

After submitting identity, the account owner can register a vehicle from My Vehicles. The submission contains make, model, year, color, registration number, and JPEG or PNG images of the registration and insurance documents. Each image is capped at 2 MiB and the full JSON body at 6 MiB, with the same dimension, pixel, concurrency, validation, and encryption controls as identity documents.

GET /api/v1/me/vehicles returns the latest metadata for each owned vehicle. POST creates a vehicle or appends a version when given an existing owned vehicle_id. Each version starts submitted and carries no approval or service eligibility. The endpoint returns metadata only. Per account, the limits are 10 vehicles, 20 versions retaining document bytes, and 250 total versions. Cleanup removes images from superseded versions older than 30 days while retaining version metadata.

Vehicle and identity uploads have separate bounded intake capacity. One request body per account can be read at a time within an API process. A body read that takes at least five seconds triggers a shared 60-second upload cooldown for that account. Verify upload buffering, slow-client protection, and timeouts at the production ingress before accepting documents.

## Driver application

Become a Driver opens Driver Details, Vehicle Details, Upload Documents, then Review & Submit. The signed-in account saves wizard progress through `PATCH /api/v1/me/driver-application` and resumes it through `GET`. Existing identity and vehicle upload routes save encrypted evidence. A successful upload alone never places evidence in the review queue.

The final `POST /api/v1/me/driver-application` binds the latest owned identity and vehicle versions in one transaction. A retry with the same binding returns the existing application. The applicant sees a single status and any rejection reason. Both checks must pass for approval. A revision invalidates the prior current application, requires explicit resubmission, and starts both checks again. A version rejected for either check cannot be reused. These transitions leave membership and marketplace eligibility unchanged.

The separate Admin Operations service reviews applications. Core owns the PostgreSQL schema, applicant writes, encrypted evidence, and derived application status. It serves applicant metadata only. Admin Operations owns reviewer access, privileged document reads, review decisions, and document-access auditing. See the service boundary in [Architecture](ARCHITECTURE.md).
