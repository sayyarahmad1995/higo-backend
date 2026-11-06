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

GET /api/v1/me/driver-submission returns the account's latest identity submission metadata, or not_submitted. POST accepts legal_name, cnic_front, and cnic_back as JSON, with the images encoded as Base64. Each successful submission creates an immutable version with submitted status. Submission leaves Driver membership, approval, and marketplace eligibility separate. Future review decisions must identify the exact version reviewed.

Uploads accept JPEG or PNG up to 1 MiB per side. The API bounds image dimensions, decodes and re-encodes the images to remove metadata, and encrypts the document bytes with AES-GCM before saving to PostgreSQL. The public API returns metadata only. Set HIGO_DRIVER_DOCUMENT_KEY to a separate Base64-encoded random 32-byte key to enable uploads. Keep the key outside PostgreSQL and protect its backup. Before production collection, validate key management, retention and deletion policy, access auditing, and the intended upload path through HTTPS ingress.

The server caps the complete JSON body at 3 MiB, limits each original and normalized image to 1 MiB, and allows up to 4096 pixels per side and 8 megapixels. It bounds simultaneous upload bodies and image processing separately. Flutter attempts to reduce large images before upload while keeping the original when recompression would increase size. Filenames and client MIME declarations do not determine acceptance.

Incomplete drafts stay on the device in memory. Cleanup removes the encrypted image bytes of superseded versions older than 30 days while keeping version metadata. At most 20 versions with document bytes are retained per account, and account deletion cascades to the stored submissions. Before collecting real CNICs, confirm retention and deletion obligations, including backups, and test physical-device picker cancellation and recovery. Establish key identifiers, rotation and recovery procedures, and a tested protected key backup before production. Slice 3C must provide separately authorized and audited reviewer access to documents.

Future document endpoints must apply bounded request bodies, per-file byte and image limits, bounded processing, and cleanup. The initial ceiling is 2 MiB per driver's license or vehicle document image. PDFs require a separate format decision and a maximum of 5 MiB if introduced.
