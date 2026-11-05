# HiGO Backend

HiGO is a Go modular monolith backed by PostgreSQL. The first vertical slice implements native phone authentication for the Flutter app.

## Run locally

1. Run `docker compose up -d --wait postgres` or provide a dedicated PostgreSQL database.
2. Load the values from [.env.example](.env.example) into the process environment. Set `HIGO_OTP_KEY` to the Base64 encoding of 32 cryptographically random bytes. For example, in PowerShell run `$env:HIGO_OTP_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))`.
3. Run `go run ./cmd/api`. Startup applies forward-only migrations. Development SMS codes appear on the local API console.
4. On an Android emulator, run the Flutter app with `flutter run --dart-define=HIGO_API_URL=http://10.0.2.2:8080`. Release builds require an HTTPS API URL.

## Tests

Run `go test ./...` and `go vet ./...`. For PostgreSQL-backed HTTP and concurrency tests, set `HIGO_TEST_DATABASE_URL` to a dedicated database and run `go test -count=1 -v ./...`. The test creates and drops its own schema. The test run reports a skip when the URL is absent.

To run the Flutter authentication smoke test, start the development API against an empty test database and redirect its standard error to a private local log. In the Flutter checkout run `flutter test test/auth_live_test.dart --dart-define=HIGO_API_URL=http://127.0.0.1:8080 --dart-define=HIGO_TEST_SMS_LOG=<absolute-log-path>`. The test uses a fixed test phone and waits for the shared SMS cooldown before testing recovery. It uses the real HTTP API and PostgreSQL with a test implementation of platform secure storage.

Production uses Twilio credentials from the environment, TLS at the ingress, and a private backend listener. See the [authentication contract](docs/AUTHENTICATION.md) for API behavior and deployment requirements.

## Handbook

- [Architecture](docs/ARCHITECTURE.md)
- [Authentication](docs/AUTHENTICATION.md)
- [Decisions](docs/DECISIONS.md)
- [Product](docs/PRODUCT.md)
