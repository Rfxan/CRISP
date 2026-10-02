# Vercel services configuration

Import this repository as one project with the **repository root** as the Vercel
Root Directory. The root `vercel.json` owns the configuration for both services;
do not select `frontend` as the project root or enter a single project-wide build
command. Services are built independently.

## Public routing

| Service | Directory | Framework | Public paths |
| --- | --- | --- | --- |
| `backend` | `backend` | FastAPI, `app.main:app` | `/api` and `/api/*` |
| `frontend` | `frontend` | Vite | All remaining paths |

The gateway preserves the original request path. FastAPI already mounts its
router at `/api`, and browser API calls use the same relative prefix. The public
health endpoint is `/api/health`. `/health`, `/docs`, and `/snapshot` are not
exposed as backend routes by this configuration. Frontend navigation falls back
to `index.html` inside the frontend service.

The former `frontend/vercel.json` rewrite to a placeholder Render hostname has
been removed. Frontend installation uses the checked-in lockfile with `npm ci`.
Backend Python is set to 3.12.

## Bindings

No internal service bindings are required by the current application. The Vite
frontend is static browser code, not a runtime function calling the backend.
The browser reaches the backend through the public `/api` gateway rewrite.
Bindings are available only to service functions at runtime; they must not be
read during Vite builds or exposed as `VITE_*` variables.

Wazuh, Keycloak, threat-intelligence feeds, and AI providers are external systems,
not services deployed by this repository. Their connection settings remain
external connection settings. A local Docker hostname or laptop `localhost`
address cannot reach those systems from a deployed function.

If a server-side frontend function or an internal worker API is added later,
declare a binding on that caller with all four required fields (`type`,
`service`, `format`, `env`) and read the injected URL inside the function.
Vercel must generate that URL; do not set it manually.

## Hosted PostgreSQL setup

The document store now supports hosted PostgreSQL using psycopg 3. Set
`CRISP_DATABASE_URL` to the provider's PostgreSQL connection URL as a Vercel
project secret, including the provider's TLS settings (for example,
`sslmode=require`, or `sslmode=verify-full` with its trust configuration).
Use a dedicated database, PostgreSQL 14 or later, and a role permitted to create
the application's tables, function, and trigger during the first connection.
The schema is initialized automatically under a database transaction lock.

`CRISP_DATABASE_URL` takes precedence over `CRISP_DATABASE_PATH`. Without the URL,
standalone development and single-host deployments retain SQLite. Deployed
Vercel instances reject a missing PostgreSQL URL rather than silently saving
into an ephemeral SQLite file. Preview deployments also require PostgreSQL and
a persistent encryption key; give previews a separate database from production.
Local `vercel dev` can continue using a disposable SQLite database.

Snapshots, connection settings, AI settings, audit events, synchronization state,
run history, and vendor mappings use the existing database document contract.
Workspace advisory transaction locks serialize updates across API processes and
workers, including the worker's due check, preventing lost updates and duplicate
jobs. Prepared statements are disabled for compatibility with transaction-pool
connection URLs. Connections close after each request or worker transaction.
Audit events have an append-only database trigger.

Existing local SQLite data is **not automatically migrated** into the hosted
database. A new database starts with no ingested business data. Re-ingest your
source data and configure connections in the deployed workspace, or arrange an
explicit migration before switching an existing production deployment.

## Remaining deployment setup

* `python -m app.worker` runs an indefinite loop and uses the configured state database.
  It is not included as a Vercel service. Continuous ingestion needs an external
  worker using the same hosted PostgreSQL URL and encryption key, or a finite,
  authenticated scheduled
  job/queue implementation. No automatic synchronization interval is promised by
  this configuration.
* Production requires `CRISP_ENV=production` and a persistent
  `CRISP_ENCRYPTION_KEY` configured as a secret in Vercel. Do not commit a key.
  The application has no user authentication, following its current workspace
  design; apply project Deployment Protection before exposing sensitive data.
* Connector endpoints must be reachable from Vercel. A private VPN on the laptop
  alone does not join a Vercel function to that network. Decide on a reachable
  connector/relay deployment separately.

Hosted PostgreSQL support was requested; the provider and synchronization
deployment are still decisions to confirm. No paid resources, production database,
or cloud deployment were created. See `backend/.env.example` for variable names.

## Local development and validation

From the repository root, use a current Vercel CLI:

```sh
npx vercel dev --local
```

`--local` runs without linking a cloud project or pulling cloud environment
variables. Set `PYTHON_DOTENV_DISABLED=1` and point `CRISP_DATABASE_PATH` at a
disposable SQLite file when testing without your local credentials and state.
Local SQLite is suitable for this check, not for deployed persistence.

The standalone `npm run dev` command uses `frontend/vite.config.js`, honors
`PORT`, and defaults to port 5173. Outside Vercel, its local API proxy defaults
to `http://127.0.0.1:8000`; set `CRISP_API_PROXY_TARGET` to override that local
development target. Under Vercel, the gateway owns `/api` routing instead.
This development variable is not an internal service binding.

Verified on 2026-10-02 with Vercel CLI 62.1.0:

* Both `backend` and `frontend` detected by `vercel dev --local`.
* `/api/health`: 200 JSON; `/` and `/dashboard`: 200 HTML.
* `/api/not-a-real-route`: backend JSON 404, not frontend HTML.
* Frontend production build passed; 11 backend API/deployment checks passed.
* Configuration accepted by the published Vercel configuration schema validator.
* Full backend suite: 95 passed, four PostgreSQL integration checks skipped in
  the SQLite run; those four passed in the separate PostgreSQL run below.
* Repeated the Vercel gateway checks with production credential handling and
  PostgreSQL enabled; `/api/risk/summary` also returned 200 JSON.
* Six PostgreSQL/deployment checks passed against an isolated PostgreSQL 18.6
  server: persistence, workspace isolation, version updates, rollback, append-only
  audit events, concurrent processes, duplicate-job prevention, and API restart
  persistence. To repeat against a disposable test database, set
  `CRISP_TEST_POSTGRES_URL` and run `python -m pytest
  tests/test_postgres_persistence.py -q` from `backend`. The two deployment guard
  checks run without a database; the four integration checks skip without that
  explicit test URL.

A cloud deployment and durable production behavior have not been validated.

References: [Services](https://vercel.com/docs/services),
[routing](https://vercel.com/docs/services/routing),
[bindings](https://vercel.com/docs/services/bindings), and
[FastAPI deployment](https://vercel.com/docs/frameworks/backend/fastapi).
