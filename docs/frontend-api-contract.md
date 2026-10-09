# TraceX frontend and API integration

The frontend uses the FastAPI routes under `backend/app/routers`. Authentication, authorization, case analysis, and remediation are performed by the backend. The frontend does not create a mock authenticated session; `VITE_USE_MOCK=true` selects only the controlled UI data fixtures.

## Authentication and session

The frontend uses a server-managed session cookie (`HttpOnly`, `Secure`, and `SameSite`) so JavaScript never reads or stores a bearer token. Requests use `withCredentials`; the backend must allow credentialed CORS for the frontend origin. Set `VITE_API_BASE_URL` to the API origin. Authentication always uses the backend, including when the case-data UI is in controlled mock mode. Without an API URL, the local default is `http://127.0.0.1:8000`.

### `POST /auth/login`

Request: `{ "email": string, "password": string }`. On success, set the session cookie and return the `AuthSession` shape from `src/types/index.ts`: `{ user: { id, email, display_name?, role, permissions? }, expires_at }`. Reject invalid credentials with `401`.

### `GET /auth/session`

Return the same `AuthSession` shape when the cookie is valid; return `401` when no valid session exists. An expired session returns `401` with `{ "detail": { "code": "SESSION_EXPIRED" } }`. This is used on initial app load and refresh.

### `POST /auth/logout`

Invalidate the server session and expire the cookie. Return `204` or a success response. The frontend clears in-memory user state even if this request fails.

`role` is `admin` or `analyst`. `permissions` is the backend's explicit list of UI action permissions (for example, `case:contain`). The frontend hides actions when permission is absent; every action must still be enforced by the backend.

## Case workflow

The investigator creates a draft with `POST /cases/intake`, including case information and a list of structured evidence items. The backend stores the case information and original evidence in MongoDB and stores a normalized event record for each submitted item. Optional identifiers unavailable to the investigator are represented as `unknown` for the current engine input contract; they are not inferred. `GET /cases/{caseId}/collected-evidence` returns the original submissions. Case-level notes are stored under the case information and updated with `PATCH /cases/{caseId}/notes`.

The investigator reviews the saved draft, then runs `POST /cases/{caseId}/analyze`. That route reads the saved case events and evidence-derived environment nodes, runs the existing engine, and stores its result. Analysis routes remain unavailable for a draft until that explicit step. Subsequent case-scoped requests provide events, attack path, root cause, blast radius, origin/evidence, remediation, and verification. The ReactFlow attack map renders engine-returned attack-path steps and their supporting evidence IDs. The environment does not infer access edges from co-occurrence alone. `POST /datasets/load-demo` remains a separate deterministic Nimbus dataset flow and is explicitly synthetic. Applying remediation and verifying it are backend operations; the UI displays returned verification state and does not synthesize success.

## Attack Origin and evidence

### `GET /cases/{caseId}/attack-origin`

Provisional response: `AttackOriginAssessment`. It may include status, suspect and state, likely origin, a backend-computed confidence score, summary, and `attribution_confirmed`. A score and a confirmed attribution must only come from backend analysis.

### `GET /cases/{caseId}/evidence`

Return an array of `EvidenceRecord` items with timestamp, event type, source, destination, device, user, IP, reason, and evidence strength. Unknown fields should be omitted or explicitly marked unknown.

### `GET /cases/{caseId}/attack-origin/trace?suspect_id={suspectId}`

Return `AttackOriginTrace` with backend-provided nodes, edges, states, and any likely-origin/confirmation fields. The UI only lays out and renders this graph; it does not infer links or score the origin.

The corresponding TypeScript shapes are declared in `src/types/index.ts`; client calls are in `src/api/client.ts`. The mock fixtures in `public/mock-api/attack-origin.json`, `attack-origin-trace.json`, and `evidence.json` are explicitly synthetic UI data. They are not real incident evidence or attribution, and they do not grant authentication or authorize actions.

## Frontend behavior on API responses

- A `401` from a protected API clears the frontend session and returns the user to `/login` with a session-ended message.
- A missing attack-origin response or empty evidence/trace is shown as unknown/inconclusive; the UI does not fill missing evidence with guessed values.
- A likely origin is not a confirmed human attacker. The UI always displays the attribution caveat.
- A `403` for a remediation action is handled as a permission denial; UI permission hiding is not security enforcement.

The backend remains the source of truth for the user, role, and permissions in all modes. Mock case fixtures are read-only; dataset loading, case creation, remediation, and verification require the connected backend.
