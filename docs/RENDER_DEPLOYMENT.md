# Deploy the backend on Render

The root `render.yaml` configures one **free Docker web service**,
`crisp-backend`, from the `main` branch of `https://github.com/Rfxan/CRISP`.
It also provisions a free PostgreSQL database, `crisp-postgres`, and connects it
to the backend automatically. It does not provision a background worker.

The service uses `Dockerfile.backend` with the repository root as its build
context. Keep the Render Root Directory empty: the Dockerfile copies paths
under `backend/` and installs the CBC solver used by the optimizer. The Docker
start command runs `python -m app.serve`, which binds `0.0.0.0` on Render's
`PORT`, defaulting to 8000 outside Render. Health checks use `/api/health`.

## Create the service

1. Open [Deploy to Render](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2FRfxan%2FCRISP),
   or choose **New > Blueprint** in the Render Dashboard and connect this repository.
2. Select `main` and the root `render.yaml`. Review the free `crisp-backend` web
   service and free `crisp-postgres` database.
3. Render supplies `CRISP_DATABASE_URL` from the database's internal connection
   URL and generates a persistent 256-bit base64 encryption key for the new
   backend. No manual secret entry is needed for this new, empty deployment.
   The database's external IP allow list is empty, so database access is private.
4. Create the Blueprint and wait for the service to become **Live**.
5. Check the generated service URL at `/api/health`, then `/api/risk/summary`.
   The health endpoint is a liveness check; the risk endpoint also verifies
   access to the configured database. Save/ingestion requests must survive a
   service restart before using the deployment for business data.

The generated key is kept when the Blueprint is synchronized again. Keep a
secure backup of it from the backend's Render environment settings. If you later
add a worker or another API deployment using the same database, give it the same
key. If connecting a database with existing encrypted CRISP credentials, preserve
the key that encrypted them; generating a new key would make those credentials
unreadable. To generate a key manually for another deployment, run:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the result in Render's secret environment settings and retain a secure
backup. Do not paste actual secrets into source files, documentation, or Git.
The Blueprint uses database references and generated secrets instead of
containing hardcoded credentials.
Render deployments enforce hosted PostgreSQL and production credential handling
even if `CRISP_ENV` was accidentally left at its development default. Local
SQLite is deliberately rejected on Render to avoid ephemeral persistence.

Existing SQLite data is not migrated automatically. New PostgreSQL databases
start with no ingested business data. For schema permissions and database
requirements, see [the PostgreSQL setup](VERCEL_DEPLOYMENT.md#hosted-postgresql-setup).

## Frontend connection

The current backend is the directly GitHub-linked free web service
`crisp-backend-github`. It deploys pushes to `Rfxan/CRISP` on `main` and reuses
the existing `crisp-postgres` database and encryption key. The previous
`crisp-backend` web service was deleted. Auto Sync is disabled on its old
Blueprint so a later sync does not recreate the deleted service. The root
Blueprint remains a template for fresh deployments; do not manually sync the
old Blueprint unless you intend to provision its resources again.

The Vercel configuration proxies `/api` and `/api/*` to the GitHub-linked backend
at `https://crisp-backend-github.onrender.com`, preserving the `/api` prefix.
The root `vercel.json` supports a repository-root Vercel project with one frontend
service. `frontend/vercel.json` supports an existing Vite project whose Root
Directory is `frontend`. Both configurations use the same backend URL.

Push the configuration to GitHub and redeploy the Vercel frontend. Open
`https://YOUR-FRONTEND.vercel.app/api/health` and then `/api/risk/summary`:
both should return backend JSON rather than the frontend HTML page. No
`VITE_API_URL` or service binding is needed; the browser uses relative `/api`
requests and Vercel forwards them to Render. If the Render service is recreated
again with a different URL, update both routing files before redeploying.

If the browser calls Render directly instead of using a same-origin proxy,
configure `CRISP_CORS_ORIGINS` with the exact frontend origins, separated by
commas. The current frontend uses same-origin `/api` URLs, so a gateway rewrite
is the intended connection path.

## Free hosting and automatic synchronization

Render's free web services spin down after inactivity and do not offer a
persistent disk. This Blueprint uses a separate Render PostgreSQL database for state.
The free plan is intended for evaluation; validate memory and compute capacity
with realistic scans and optimizer workloads before production use.

Automatic 30-second ingestion requires a separately hosted
`python -m app.worker` process with the same database URL and encryption key.
Render background workers require a paid compute plan and are not added by
this backend-only Blueprint. On-demand refresh and synchronization remain API
actions. The free database expires after 30 days and is eventually deleted unless
upgraded. Only one free PostgreSQL database can be active in a Render workspace.
If your workspace already has one, reuse it explicitly or choose another workspace;
do not silently upgrade a resource to a paid plan. Do not treat this expiring
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

* The GitHub-linked Docker deployment became Live on Render; `/api/health`
  and `/api/risk/summary` returned 200 JSON using the retained PostgreSQL database.
* The frontend production build passed and both Vercel routing configurations
  passed validation against Vercel's published configuration schema.

References: [Blueprint specification](https://render.com/docs/blueprint-spec),
[Docker deployment](https://render.com/docs/docker),
[environment variables](https://render.com/docs/environment-variables), and
[free hosting limits](https://render.com/docs/free).
