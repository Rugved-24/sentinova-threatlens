# ThreatLens deployment notes

## Compose production profile

1. Copy `.env.example` to `.env` and set at least `SECRET_KEY`, `POSTGRES_PASSWORD`, and `CORS_ORIGINS`.
2. Generate a local certificate:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\deploy\generate-certs.ps1
   ```

3. For a local demonstration, build and start the base Compose file. For a non-demo deployment,
   use the production override; it fails immediately when required secrets are missing and removes
   the direct API host port:

   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.production.yml build
   docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
   ```

4. Open `https://localhost:8443`. Replace the self-signed certificate with a trusted certificate before exposing the service.

Services: PostgreSQL, Redis, Elasticsearch, API, Celery worker, Celery beat, and nginx. The base file
exposes API port `8000` for local diagnostics; the production override removes it so traffic enters
through TLS nginx only.

## Monitoring

```powershell
docker compose --profile monitoring up -d
```

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (default `admin` / `threatlens`; change it)

## Backup and restore

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\backup.ps1
powershell -ExecutionPolicy Bypass -File .\deploy\restore.ps1 -InputFile .\data\backups\<file>.dump
```

Backups use `pg_dump -Fc`. Restore stops API/worker/beat, runs `pg_restore --clean --if-exists`, and restarts them. Verify `/api/v1/health` afterward. Audit and incident-timeline append-only triggers remain active; restore is an administrative operation.

## Kubernetes

`deploy/k8s/` contains namespace, config, secret example, PVC, PostgreSQL, Redis, Elasticsearch, API, worker, beat, seed Job, ingress, and kustomization manifests.

```powershell
kubectl kustomize .\deploy\k8s
kubectl apply -k .\deploy\k8s
```

Create `threatlens-secrets` from `secret.example.yaml` with real values and provide a `threatlens-tls` secret plus a storage class that supports `ReadWriteOnce`. The manifests were render-validated only; no Kubernetes cluster was available in this environment.

## Operational limits

- Elasticsearch security is disabled in the Compose profile for local simplicity. Enable TLS/authentication before exposing it.
- Redis uses AOF with an LRU cap. It is an event bus and Celery broker, not the system of record.
- The audit hash chain detects tampering but is not an external immutable ledger.
- Feed API keys and TAXII credentials are optional; key-gated feeds remain disabled or use documented fallback behavior when unset.
