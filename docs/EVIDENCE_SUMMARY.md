# Public evidence summary

## Automated quality and security checks

- 188 backend tests passed.
- Ruff static analysis passed.
- Bandit security analysis passed.
- pip-audit reported no known Python dependency vulnerabilities at verification time.
- ESLint passed.
- TypeScript and Vite production build passed.
- `npm audit --omit=dev` reported no known production dependency vulnerabilities at verification time.
- All nine authenticated UI routes passed browser smoke testing without unexpected console, page or request failures.

## Runtime and recovery evidence

- API health returned `status=ok` and `database=ok`.
- PostgreSQL, Redis, Elasticsearch, API, Celery worker and Celery beat workloads were ready on AWS k3s staging.
- Celery worker responded to ping.
- Audit chain verification passed.
- A PostgreSQL custom-format backup was restored into a temporary database and queried successfully.
- A bounded cloud check completed 300 requests at concurrency 20 with 300 successes and 0 failures.
- Trusted Let’s Encrypt TLS and HTTP-to-HTTPS redirection were configured.

## Honest limitations

- The AWS environment is single-node staging, not multi-node production.
- The measured cloud p95 latency was about 2024 ms, above the PRD target of 400 ms.
- Targets for 50,000 indicators per hour, 200 concurrent users, 10 million searchable documents and 99.5% monthly availability have not been demonstrated.
- Long-duration uptime evidence requires a sustained observation period.
- Live SMTP and third-party intelligence integrations require external provider accounts and credentials.

These limitations should remain in the public README or compliance document. Removing them would turn bounded staging evidence into an unsupported production claim.
