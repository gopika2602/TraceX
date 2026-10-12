# TraceX

**AI-Powered Attack Path and Root-Cause Investigator**
See the attack. Trace the evidence. Find the root cause.

TraceX is the existing React/TypeScript frontend, FastAPI backend, MongoDB persistence layer, and deterministic NetworkX investigation engine. Authentication, case ownership, evidence intake, case analysis, attack-path assessment, origin review, blast-radius assessment, remediation, and verification are kept on the existing application flow.

The public `/` route is a cinematic, responsive product landing page. It uses illustrative example content only and does not expose case records. `/login` remains the existing backend authentication flow; authenticated visitors at `/` are sent to `/cases`. A persisted dark-neon or soft-blush theme preference applies to both landing and workspace. Reduced-motion preferences disable the landing transitions. The authenticated dashboard uses live API case counts and preserves the existing evidence, graph, timeline, root-cause, origin, blast-radius, and remediation routes.

## AI Investigation Agent

The protected `/agent` workspace accepts an incident narrative and multiple CSV, JSON, TXT, or LOG files. It creates an extraction preview with source and line/row references, shows missing timestamps and possible duplicate records, and requires explicit review before approved evidence can be imported as a normal TraceX investigation. Import uses the existing Mongo-backed case/evidence API, then immediately invokes the same deterministic case analysis as the rest of TraceX. The API reports when case persistence succeeded but analysis could not complete, rather than fabricating a result.

The current parser is deterministic and does **not** call an AI service. It extracts only fields present in the input or clearly identifiable from text. Its heuristic confidence is not calibrated and is not a probability. Statements remain unverified until reviewed. PDF parsing, connected SIEM sources, LLM summaries, and external integrations are not configured. A timezone-aware full timestamp is required for approval; the user may edit an extracted event before approval.

Uploads are capped at 3 MiB per file, 8 MiB for the combined request, and 500 records. Accepted formats are plain-text CSV, JSON, TXT, and LOG. Uploaded bytes are stored with the owner-scoped extraction record for provenance; records and their original extraction are only retrievable by that authenticated owner. Audit records capture action, actor, target, and counts without copying incident text or credentials.

## Run locally

Frontend (from the repository root):

```powershell
npm install
$env:VITE_API_BASE_URL = 'http://127.0.0.1:8000'
$env:VITE_USE_MOCK = 'false'
npm run dev
```

Backend (from the repository root; configure a MongoDB URI and JWT secret first):

```powershell
python -m pip install -r backend/requirements.txt
$env:MONGODB_URI = 'mongodb://127.0.0.1:27017'
$env:JWT_SECRET_KEY = 'use-a-local-secret-of-at-least-32-characters'
$env:APP_ENV = 'development'
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Deployment and required environment variables are described in [DEPLOY.md](DEPLOY.md). Never put production credentials in source control.

## Verification

Backend tests: `python -m pytest backend/tests engine/tests -q` (run with the backend and engine dependencies installed). Frontend production build: `npm run build`.

MongoDB Atlas, Render, Vercel, and production records are not modified by local tests. Live service readiness must be checked separately at the deployed `/health/ready` endpoint.
