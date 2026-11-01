# ThreatLens AWS Cloud Deployment Evidence

## Deployment

- Date: 31 October 2026
- Environment: AWS Free Plan staging
- Region: Asia Pacific Sydney (`ap-southeast-2`)
- Compute: EC2 `m7i-flex.large`
- Orchestration: k3s Kubernetes `v1.36.5+k3s1`
- Public URL: https://3-107-94-150.sslip.io
- TLS: Trusted Let's Encrypt certificate managed by cert-manager `v1.21.3`
- HTTP policy: Permanent redirect to HTTPS
- Application mode: Production with demo mode disabled

## Workload status

- API: Running and ready
- PostgreSQL: Running and ready
- Redis: Running and ready
- Elasticsearch: Running and ready
- Celery worker: Running and responding to ping
- Celery beat: Running
- Seed job: Completed
- Audit chain: Valid

## Acceptance evidence

- Public API health: `status=ok`, `database=ok`, `demo_mode=false`
- Authenticated production login: Passed
- Browser smoke: All 9 routes passed with no console, page, or request problems
- Bounded load check: 300 requests at concurrency 20; 300 successes and 0 failures
- Observed throughput: 15.94 requests per second
- Mean latency: 1235.29 ms
- P95 latency: 2024.57 ms

## Backup and recovery

- PostgreSQL custom-format backup created in the cloud
- Backup restored into a temporary database and queried successfully
- Restored row counts: 1171 indicators, 0 security events, 10 audit entries
- Temporary restore database removed after verification
- A verified backup is retained privately outside the public repository.
- SHA-256: `A9A7EE88C2F4CEF33400EEAFC4660E0C5DC983C1B70550882010F51FE77144B4`

## Monitoring

- A systemd timer checks the public HTTPS health endpoint every five minutes.
- The initial monitored check completed successfully.
- Twenty-four-hour uptime evidence requires the observation period to elapse.

## Credential handling

- Kubernetes secrets were generated on the server and were not written to this report.
- Administrator credentials and the SSH private key are stored outside the repository with restricted local permissions.

## Operational constraints

- The deployment uses AWS promotional Free Plan credits and should be stopped when not collecting uptime evidence.
- The public hostname is IP-derived. Stopping and restarting the instance may change its public IP and require issuing a new hostname and certificate.
- SMTP, outbound webhook, VirusTotal, AbuseIPDB and other provider keys require the corresponding third-party accounts and user verification before they can be activated.
