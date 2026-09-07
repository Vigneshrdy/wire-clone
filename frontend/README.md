# SIH 26145 Analyst Console

Next.js App Router console for the SIH passive threat-detection API. The browser talks to strict same-origin BFF routes; only the Next.js server connects to FastAPI.

## Local development

Start FastAPI at `http://127.0.0.1:8000`, then:

```bash
npm ci
npm run dev
```

Open `http://127.0.0.1:3000`. Override the server-side backend target with `FASTAPI_BASE_URL`. Set the build-time `NEXT_PUBLIC_WS_URL` when FastAPI is not reachable at the current hostname on port 8000; Docker exposes it as a build argument.

Management actions are locked until an operator enters the API token under **System > Operator access**. The token is held in `sessionStorage`, never in a public environment variable.

## Verification

```bash
npm run typecheck
npm run lint
npm test
npm run design:check
npm run build
npm run e2e
```

Playwright expects the console on port 3000 and FastAPI on port 8000. Chromium is configured at `/usr/bin/chromium` for this workspace.

See `DESIGN_SYSTEM.md` for interaction and visual rules and `THIRD_PARTY_RESOURCES.md` for dependency provenance.
