# Aegis Dashboard — Web (React)

A modern React + TypeScript SPA over the FastAPI dashboard's **JSON API**. This is the
makeover of the legacy Jinja2+htmx UI (`services/dashboard`, still running); it consumes the
same backend and shared Postgres `alerts` table.

**Stack:** Vite · React 18 · TypeScript · Tailwind CSS · TanStack Query · React Router · lucide-react.

## Views
- **Alerts** (`/`) — live alert queue (filter all / malicious), severity + verdict badges.
- **Alert detail** (`/alert/:id`) — summary, MITRE TTPs, **XAI feature-attribution chart**,
  observables, annotation, and the **Step-6 verdict + feedback** form
  (true/false positive · explanation useful · flag for retraining).
- **Approvals** (`/approvals`) — pending gated **block/isolate** actions; Approve/Reject relays
  the decision to the orchestrator via the backend (the browser never holds the SOAR token).
- **Metrics** (`/metrics`) — pipeline stats + confusion matrix.

## Backend contract (FastAPI JSON API, `services/dashboard/main.py`)
`GET /api/summary` · `GET /api/alerts` · `GET /api/alerts/{id}` · `GET /api/metrics` ·
`GET /api/approvals` · `POST /api/approvals/{id}/decide` · `POST /api/alerts/{id}/feedback`.

## Run

**With the stack (recommended):** the `dashboard-web` compose service builds this image and
serves it on **:3000**, proxying `/api` to the `dashboard` service.
```bash
docker compose up -d --build dashboard dashboard-web    # → http://localhost:3000
```

**Local dev (needs Node 20):**
```bash
npm install
VITE_API_TARGET=http://localhost:8080 npm run dev       # Vite :5173, proxies /api → :8080
npm run typecheck                                        # optional strict type check
```

## Notes
- The SOAR approval **token stays server-side** in the FastAPI dashboard; the SPA only calls
  `/api/...`, so no secret reaches the browser.
- The build uses `vite build` (esbuild) — `npm run typecheck` runs `tsc --noEmit` separately.
- nginx proxies `/api` → `http://dashboard:8080`; change `nginx.conf` if the backend moves.
