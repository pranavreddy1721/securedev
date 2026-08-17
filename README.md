# SecureDev

A lightweight, web-based DevSecOps security-scanning platform for MERN-stack projects.
Upload a `.zip` or connect a GitHub repo, and SecureDev orchestrates `npm audit`, a
regex-based secret scanner, and Semgrep in parallel, then rolls the results up into a
single weighted 0–100 security score with a downloadable PDF report.

**The core contribution is not the scanning itself** — it's the orchestration layer and
the unified, severity-weighted scoring model on top of existing open-source tools.

## Project structure

```
securedev/
├── backend/           Express API — auth, orchestration, scoring, PDF reports
│   └── src/
│       ├── config/         DB connection + the scoring formula (single source of truth)
│       ├── models/         Mongoose schemas: User, Project, Scan
│       ├── middleware/     JWT auth, rate limiting, multer upload config, error handler
│       ├── controllers/    Route handlers
│       ├── routes/         Express routers
│       ├── scanners/       npm audit / secret / Semgrep / heuristic engine wrappers
│       ├── orchestrator/   Runs all engines in parallel via Promise.allSettled
│       ├── scoring/        Implements the weighted scoring formula
│       ├── reports/        PDF generation (pdfkit)
│       └── utils/          crypto (token encryption), JWT helpers, temp dir, zip/repo handling
├── frontend/           React + Tailwind dashboard
│   └── src/
│       ├── pages/          Landing, Login, Signup, Dashboard, ScanResults, ScanHistory
│       ├── components/     RadialGauge, SeverityBadge, Navbar, modals, async states
│       └── context/        Auth + theme (dark mode) state
└── docs/
    └── ARCHITECTURE.md      Detailed write-up for your report/viva
```

## Local setup

### Prerequisites
- Node.js 18+
- MongoDB running locally (or an Atlas connection string)
- Python 3 + pip (for Semgrep — `pip install semgrep`)
- A GitHub OAuth App (for the GitHub-connect flow)

### Backend

```bash
cd backend
cp .env.example .env
# edit .env: set MONGODB_URI, JWT secrets, GITHUB_CLIENT_ID/SECRET, GITHUB_TOKEN_ENC_KEY
npm install
npm run dev
```

Generate a valid `GITHUB_TOKEN_ENC_KEY` (32 random bytes, base64):
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### Frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Visit `http://localhost:5173`.

## What's built vs. stubbed (v1 status)

**Fully implemented:**
- JWT auth (access + refresh, bcrypt, rate-limited)
- GitHub OAuth (`public_repo` scope only, token encrypted at rest)
- Zip upload (25MB limit, zip-slip protected) and GitHub repo intake
- All 3 named scan engines (npm audit, secret scanner, Semgrep) + orchestration via `Promise.allSettled`
- Scoring engine (hybrid severity-weighted, diminishing-returns formula — see `docs/ARCHITECTURE.md`)
- Dashboard, scan results, scan history (with score trend chart), PDF report, dark mode

**Known v1 limitations (by design, not oversights):**
- **Insecure File Uploads, Broken Access Control, Sensitive Data Exposure** are covered by
  lightweight regex/pattern heuristics, not full static/dataflow analysis. Findings from
  these are tagged `heuristic: true` and labeled as such in the UI/PDF.
- No job queue — scans run as fire-and-forget async work on the same Node process. Fine for
  a single Render instance and a student-project scale; would need Bull/Redis to scale out.
- No cloud storage — uploaded zips and cloned repos live in an ephemeral OS temp dir and are
  deleted after each scan. Re-scanning a zip-sourced project requires re-uploading.
- npm audit parsing targets npm v7+'s JSON shape; npm v6's older `advisories` format isn't handled.
- Semgrep uses public rulesets only (`p/javascript`, `p/react`, `p/nodejsscan`) — no custom
  MERN-specific rules yet.

## Deployment

- **Frontend:** Cloudflare Pages — build command `npm run build`, output directory `dist`.
  Set `VITE_API_BASE_URL` to your Render backend URL in Pages' environment variables.
- **Backend:** Render — build command should install Semgrep alongside npm deps:
  `npm install && pip install semgrep`. Set all `.env.example` variables in Render's
  environment settings. Set `CLIENT_ORIGIN` to your Cloudflare Pages domain so CORS allows it.
