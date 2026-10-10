# TraceX API

FastAPI backend for the existing TraceX React application. It uses MongoDB for users, revocable sessions, uploaded telemetry, environment graphs, cases, analyses, and remediation verification. The API follows the frontend's HttpOnly-cookie session contract; the browser never needs to read a JWT.

## Run locally

1. Start MongoDB locally (default URI `mongodb://127.0.0.1:27017`).
2. Create a virtual environment, install `backend/requirements.txt`, then run from the repository root:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r backend\requirements.txt
   pip install -e engine
   uvicorn backend.app.main:app --reload
   ```

3. Run the frontend with `VITE_USE_MOCK=false` and `VITE_API_BASE_URL=http://127.0.0.1:8000`. The frontend's existing mock mode remains available when `VITE_USE_MOCK=true`.
4. Open `http://127.0.0.1:8000/docs` for the API documentation and `http://127.0.0.1:8000/health` for a process health check.

Development generates an ephemeral signing key at process startup when `JWT_SECRET_KEY` is absent, so existing sessions become invalid after a restart. Production requires a secret of at least 32 characters. Never commit a real secret. Copy `backend/.env.example` into a local environment file and replace the example value before a production deployment.

On first startup with an empty `users` collection, setting both `ADMIN_EMAIL` and `ADMIN_PASSWORD` creates one Admin account. The password uses the same bcrypt hashing as normal registration. If any account already exists, bootstrap makes no changes. Remove the bootstrap variables after verifying the first Admin can sign in. Registering an account through `POST /auth/register` creates an Analyst by default. An account becomes Admin only when its email is on the server-side `TRACEX_BOOTSTRAP_ADMIN_EMAILS` allowlist at registration time. The role is never accepted from the client. Admins can apply remediation and reset the deterministic demo; analysts can read and create cases.

## Nimbus demo

Generate the deterministic scenario from the repository root:

```powershell
python scenarios\generate_nimbus.py
```

Sign in, then call `POST /datasets/load-demo` to load the 40-event scenario. Create a case with `POST /cases`; the API runs the existing `engine` package and persists the result. Uploads accept JSON event arrays and an environment graph, with a 10 MB per-file and 100,000 event limit.

## Docker Compose

Create a local `.env` at the repository root (ignored by Git) containing a random `JWT_SECRET_KEY` of at least 32 characters. Optionally set `TRACEX_BOOTSTRAP_ADMIN_EMAILS` to a comma-separated allowlist, then run `docker compose up --build`. The API is at port 8000 and the frontend at port 8080. MongoDB data is stored in the named `tracex_mongodb` volume. For HTTPS production, set `SESSION_COOKIE_SECURE=true` and configure trusted HTTPS origins.

## Session and authorization

- `POST /auth/register`, `POST /auth/login`, `GET /auth/session`, `POST /auth/logout`
- JWTs are stored only in an HttpOnly cookie; an Authorization Bearer header is also accepted for API tooling.
- Session IDs are persisted and revocable; MongoDB TTL removes expired sessions.
- MongoDB is the source of truth for current user role and permissions on each request.
- Admin-only: remediation apply/verify, demo reset. Dataset upload/demo load requires a signed-in user.

The backend is deliberately independent of the frontend deployment: it does not require the engine author's workstation or the React app's mock API to be running.
