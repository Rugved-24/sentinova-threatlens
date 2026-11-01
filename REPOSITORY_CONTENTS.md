# Repository contents and exclusions

This public repository copy was sanitized before publication.

## Included

- Backend source and automated tests
- Frontend source, dependency manifests, and E2E smoke test
- Docker, Docker Compose, and Kubernetes deployment files
- Safe configuration examples (`.env.example` and `deploy/k8s/secret.example.yaml`)
- Verification, backup, restore, and certificate-generation scripts
- Project documentation, cloud evidence, and the cross-device setup guide

## Intentionally excluded

- Real `.env` configuration and populated Kubernetes secrets
- AWS staging private key and cloud administrator credential note
- Generated TLS private keys and certificates
- Cookies, login responses, browser/API sessions, and tokens
- SQLite/PostgreSQL data, reports, database dumps, and backups
- `.venv`, `node_modules`, `frontend/dist`, caches, coverage output, and previous Git history
- Real SMTP, webhook, threat-intelligence, or cloud API credentials

## Important distinction

The demo users and demo password referenced by the source are synthetic, public evaluation fixtures. They are not personal, cloud, or production credentials. Replace or disable demo access before any real deployment.

See `docs/ThreatLens_Setup_and_Run_Guide.docx` for setup, verification, Kubernetes, and safe-sharing instructions.
