# Deploy the backend on Render

The root `render.yaml` configures one **free Docker web service**,
`crisp-backend`, from the `main` branch of `https://github.com/Rfxan/CRISP`.
It does not provision a database or a background worker.

The service uses `Dockerfile.backend` with the repository root as its build
context. Keep the Render Root Directory empty: the Dockerfile copies paths
under `backend/` and installs the CBC solver used by the optimizer. The Docker
start command runs `python -m app.serve`, which binds `0.0.0.0` on Render's
`PORT`, defaulting to 8000 outside Render. Health checks use `/api/health`.

## Create the service

1. In the Render Dashboard, choose **New > Blueprint** and connect this repository.
2. Select `main` and the root `render.yaml`. Review the free `crisp-backend` web service.
3. Enter the secrets requested by the Blueprint:
   * `CRISP_DATABASE_URL`: a dedicated hosted PostgreSQL connection URL. Use the
     provider's TLS settings for an external connection. A Render Postgres
     database's internal connection URL can be used by services in its region.
   * `CRISP_ENCRYPTION_KEY`: a persistent Fernet key. If this database already
     contains encrypted CRISP credentials, use the same key that encrypted them.
4. Create the Blueprint and wait for the service to become **Live**.
5. Check the generated service URL at `/api/health`, then `/api/risk/summary`.
   The health endpoint is a liveness check; the risk endpoint also verifies
   access to the configured database. Save/ingestion requests must survive a
   service restart before using the deployment for business data.

For a new empty database, generate a key once in your terminal:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the result in Render's secret environment settings and retain a secure
backup. Do not paste actual secrets into source files, documentation, or Git.
The Blueprint prompts for credentials instead of containing hardcoded values.
Render deployments enforce hosted PostgreSQL and production credential handling
even if `CRISP_ENV` was accidentally left at its development default. Local
SQLite is deliberately rejected on Render to avoid ephemeral persistence.

Existing SQLite data is not migrated automatically. New PostgreSQL databases
start with no ingested business data. For schema permissions and database
requirements, see [the PostgreSQL setup](VERCEL_DEPLOYMENT.md#hosted-postgresql-setup).

## Frontend connection

The checked-in Vercel configuration still deploys its own backend service. It
does not automatically send traffic to Render. Once the real Render URL exists,
replace the Vercel backend service routes with an external `/api` rewrite to
that URL, preserving the `/api` prefix. Remove the Vercel backend service only
as part of that change. No guessed Render hostname is committed.

If the browser calls Render directly instead of using a same-origin proxy,
configure `CRISP_CORS_ORIGINS` with the exact frontend origins, separated by
commas. The current frontend uses same-origin `/api` URLs, so a gateway rewrite
is the intended connection path.

## Free hosting and automatic synchronization

Render's free web services spin down after inactivity and do not offer a
persistent disk. This Blueprint uses external PostgreSQL for durable state.
The free plan is intended for evaluation; validate memory and compute capacity
with realistic scans and optimizer workloads before production use.

Automatic 30-second ingestion requires a separately hosted
`python -m app.worker` process with the same database URL and encryption key.
Render background workers require a paid compute plan and are not added by
this backend-only Blueprint. On-demand refresh and synchronization remain API
actions. Free Render PostgreSQL databases also expire; do not treat an expiring
evaluation database as permanent production storage.

The application has no user login, following the current workspace design.
Restrict access through a trusted gateway before ingesting sensitive data.
Connector URLs must be reachable from Render; a laptop `localhost` address or
Docker-only hostname cannot reach the laptop from the deployed backend.

## Validation

* Root Blueprint accepted by Render's published JSON schema.
* 13 focused deployment/persistence checks passed; four PostgreSQL integration
  checks skipped because no test database was running for this change.
* The actual `app.serve` process started on an injected port with Render's
  production guards, and `/api/health` returned 200.
* PostgreSQL integration was tested during the preceding Vercel/PostgreSQL change.

Docker image building and a live Render deployment have not been verified in
this session. Render account access and hosted database settings are required to
complete deployment. An automatic approval review blocked a command that also
attempted to restart the isolated PostgreSQL test server; it supplied only
"blocked by policy". Blueprint validation was completed independently.

References: [Blueprint specification](https://render.com/docs/blueprint-spec),
[Docker deployment](https://render.com/docs/docker),
[environment variables](https://render.com/docs/environment-variables), and
[free hosting limits](https://render.com/docs/free).
