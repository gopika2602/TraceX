# TraceX frontend API contract proposal

**Status: provisional.** The backend team owns authentication, authorization, evidence correlation, trace generation, and confidence scoring. The frontend types and endpoint shapes below are integration placeholders, not a claim about an already deployed API. Confirm them with Harini before connecting production.

## Authentication and session

The frontend uses a server-managed session cookie (`HttpOnly`, `Secure`, and `SameSite`) so JavaScript never reads or stores a bearer token. Requests use `withCredentials`; the backend must allow credentialed CORS for the frontend origin. Set `VITE_API_BASE_URL` to the HTTPS API origin outside local development. The mock-mode session stores only demo user metadata in `sessionStorage` and is never used as backend authentication. Its user and role come from `public/mock-api/auth-user.json`, using the same session shape as the API. The fixture can be edited to preview another role; the live role always comes from the backend response.

### `POST /auth/login`

Request: `{ "email": string, "password": string }`. On success, set the session cookie and return the provisional `AuthSession` shape from `src/types/index.ts`: `{ user: { id, email, display_name?, role, permissions? }, expires_at }`. Reject invalid credentials with `401`.

### `GET /auth/session`

Return the same `AuthSession` shape when the cookie is valid; return `401` when no valid session exists. For an expired formerly valid session, return `401` with `{ "code": "SESSION_EXPIRED" }`; for no session, a different code or empty response lets the UI avoid incorrectly claiming expiry. This is used on initial app load and refresh.

### `POST /auth/logout`

Invalidate the server session and expire the cookie. Return `204` or a success response. The frontend clears in-memory user state even if this request fails.

`role` is `admin` or `analyst`. `permissions` is the backend's explicit list of UI action permissions (for example, `remediation:apply`). The frontend hides actions when permission is absent; every action must still be enforced by the backend.

## Attack Origin and evidence

### `GET /cases/{caseId}/attack-origin`

Provisional response: `AttackOriginAssessment`. It may include status, suspect and state, likely origin, a backend-computed confidence score, summary, and `attribution_confirmed`. A score and a confirmed attribution must only come from backend analysis.

### `GET /cases/{caseId}/evidence`

Return an array of `EvidenceRecord` items with timestamp, event type, source, destination, device, user, IP, reason, and evidence strength. Unknown fields should be omitted or explicitly marked unknown.

### `GET /cases/{caseId}/attack-origin/trace?suspect_id={suspectId}`

Return `AttackOriginTrace` with backend-provided nodes, edges, states, and any likely-origin/confirmation fields. The UI only lays out and renders this graph; it does not infer links or score the origin.

The corresponding provisional TypeScript shapes are declared in `src/types/index.ts`; client calls are in `src/api/client.ts`. The mock fixtures in `public/mock-api/attack-origin.json`, `attack-origin-trace.json`, and `evidence.json` are explicitly synthetic demo data. They are not real incident evidence, authentication, or attribution.

## Frontend behavior on API responses

- A `401` from a protected API clears the frontend session and returns the user to `/login` with a session-ended message.
- A missing attack-origin response or empty evidence/trace is shown as unknown/inconclusive; the UI does not fill missing evidence with guessed values.
- A likely origin is not a confirmed human attacker. The UI always displays the attribution caveat.
- A `403` for a remediation action is handled as a permission denial; UI permission hiding is not security enforcement.

For mock role review, edit `public/mock-api/auth-user.json`. Demo permissions remain empty; no demo remediation or containment action is authorized. In production, the backend remains the source of truth for the user, role, and permissions.
