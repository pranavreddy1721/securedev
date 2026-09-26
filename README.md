# SecureDev

<div align="center">

<!-- Banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=10b981&height=200&section=header&text=SecureDev&fontSize=56&fontColor=ffffff&fontAlignY=38&desc=Scan%20%E2%80%A2%20Assess%20%E2%80%A2%20Secure&descAlignY=58&descSize=20&animation=fadeIn" width="100%" />

<br/>

<!-- Badges -->
<p>
  <img src="https://img.shields.io/badge/React-18.3.1-61DAFB?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Express-4.19-000000?style=for-the-badge&logo=express&logoColor=white" />
  <img src="https://img.shields.io/badge/MongoDB-Mongoose-47A248?style=for-the-badge&logo=mongodb&logoColor=white" />
  <img src="https://img.shields.io/badge/Semgrep-Static%20Analysis-111827?style=for-the-badge&logo=semgrep&logoColor=white" />
</p>
<p>
  <img src="https://img.shields.io/badge/npm%20audit-Dependency%20Scan-CB3837?style=for-the-badge&logo=npm&logoColor=white" />
  <img src="https://img.shields.io/badge/JWT-Authentication-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" />
  <img src="https://img.shields.io/badge/PDFKit-PDF%20Reports-DC2626?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" />
  <img src="https://img.shields.io/badge/Tailwind%20CSS-3.4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />
</p>

<br/>

> **A lightweight DevSecOps platform for MERN projects — bringing dependency scanning, secret detection, source-code analysis, unified scoring, and security reporting into one workflow.**

[🚀 Live Demo](https://securedev.pages.dev/) &nbsp;•&nbsp; [📖 Architecture](docs/ARCHITECTURE.md) &nbsp;•&nbsp; [🐛 Report Bug](https://github.com/pranavreddy1721/securedev/issues) &nbsp;•&nbsp; [💡 Request Feature](https://github.com/pranavreddy1721/securedev/issues)

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🔎 Security Scanning](#-security-scanning)
- [📊 Assessment & Scoring](#-assessment--scoring)
- [🧱 Architecture](#-architecture)
- [🗂️ Project Structure](#️-project-structure)
- [🛠️ Tech Stack](#️-tech-stack)
- [🔐 Security Controls](#-security-controls)
- [📄 PDF Reporting](#-pdf-reporting)
- [🧪 Testing](#-testing)
- [🚀 Deployment](#-deployment)
- [⚙️ Environment Variables](#️-environment-variables)
- [▶️ Getting Started](#️-getting-started)
- [⚠️ Limitations](#️-limitations)
- [🤝 Contributing](#-contributing)

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔎 Security Scanning
- 📦 **Dependency scanning** with `npm audit`
- 🔑 **Secret detection** for credential-like values
- 🧩 **Semgrep source-code analysis** for security patterns
- 🧠 Lightweight heuristic checks for selected application-security risks
- ⚡ Scan engines orchestrated in parallel

</td>
<td width="50%">

### 📊 Unified Assessment
- 🎯 Weighted **0–100 security score**
- 🚦 Risk band based on the calculated score
- 🏷️ Severity classification: Critical, High, Medium, Low
- 🧹 Cross-engine finding normalization and deduplication
- ✅ Explicit **complete / incomplete** assessment state

</td>
</tr>
<tr>
<td width="50%">

### 👤 Authentication & Access
- JWT access + refresh authentication
- Password hashing with bcrypt
- Protected API routes
- Rate-limited authentication endpoints
- Refresh-token workflow

</td>
<td width="50%">

### 📁 Project Intake
- `.zip` project upload
- GitHub repository intake flow
- 25 MB upload limit
- ZIP extraction with zip-slip protection
- Ephemeral project workspace cleaned after scan

</td>
</tr>
<tr>
<td width="50%">

### 🖥️ Developer Experience
- Dashboard with project/scan history
- Scan progress and async states
- Security findings grouped by category
- Plain-language remediation guidance
- Dark mode

</td>
<td width="50%">

### 📄 Reporting
- Professional downloadable PDF report
- Executive summary and overall score
- Security-area breakdown
- Scanner coverage and status
- Detailed findings with recommended actions

</td>
</tr>
</table>

---

## 🔎 Security Scanning

SecureDev combines three core engines and supplementary heuristics into one assessment workflow.

| Engine | What it does | Output |
|---|---|---|
| **npm audit** | Checks dependencies against npm's known vulnerability data | Dependency findings |
| **Secret Scanner** | Detects credential-like values and secret patterns in project files | Secret findings |
| **Semgrep** | Applies configurable rules to JavaScript/Node/Express source code | Static-analysis findings |
| **Heuristic Scanner** | Lightweight pattern checks for uploads, access control and sensitive-data exposure | Heuristic findings |

Core engine results are orchestrated with `Promise.allSettled`, so one failing scanner can be represented explicitly rather than silently treated as clean.

### Deterministic scanning behavior

SecureDev does **not** create a new `package-lock.json` during a scan. For dependency scanning, an uploaded project with `package.json` is expected to provide its lockfile so the result remains reproducible for the same input.

---

## 📊 Assessment & Scoring

The assessment layer converts raw findings into a consistent security view.

### Security areas

| Security area | Weight | Purpose |
|---|---:|---|
| Dependency Security | **30%** | Third-party packages and known vulnerabilities |
| Authentication | **20%** | Protection around identity and access |
| Secrets Detection | **20%** | Credential and secret-like values in source |
| Application Security | **20%** | Code-level security risks and patterns |
| Configuration | **10%** | Security-sensitive application configuration |

### Assessment flow

```text
Project
   ↓
Scan engines run in parallel
   ↓
Collect raw findings
   ↓
Normalize + deduplicate
   ↓
Classify by category + severity
   ↓
Calculate weighted security score
   ↓
Present results + PDF report
```

### Incomplete assessments

When a **core engine** fails, SecureDev marks the assessment as `incomplete` and does not present a comprehensive score. This prevents missing scanner output from being interpreted as a clean result.

---

## 🧱 Architecture

```text
┌──────────────────────┐
│      React UI        │
│  Landing / Auth /    │
│  Dashboard / Results │
└──────────┬───────────┘
           │ HTTPS / JSON
           ▼
┌──────────────────────┐
│  Node + Express API  │
│ Auth • Projects      │
│ Scans • Reports      │
└──────────┬───────────┘
           │
           ▼
┌────────────────────────────────────┐
│        Scan Orchestrator            │
│         Promise.allSettled          │
└──────┬───────────┬───────────┬─────┘
       │           │           │
       ▼           ▼           ▼
  npm audit   Secret Scanner  Semgrep
       │           │           │
       └───────────┴───────────┘
                   │
                   ▼
        Finding Normalization
                   │
                   ▼
          Weighted Scoring
                   │
             ┌─────┴─────┐
             ▼           ▼
       Results UI     PDF Report
```

Supporting services include MongoDB for persistence and temporary filesystem storage for scan workspaces.

---

## 🗂️ Project Structure

```text
securedev/
├── backend/
│   ├── src/
│   │   ├── config/          # Database + scoring configuration
│   │   ├── controllers/     # Auth, GitHub, projects, scans
│   │   ├── middleware/      # Auth, rate limiting, uploads, errors
│   │   ├── models/          # User, Project, Scan
│   │   ├── orchestrator/    # Parallel scan orchestration
│   │   ├── reports/         # PDF generation
│   │   ├── routes/          # Express route modules
│   │   ├── scanners/        # npm audit, secret, Semgrep, heuristics
│   │   ├── scoring/         # Weighted scoring engine
│   │   └── utils/           # JWT, crypto, temp dirs, GitHub/repo helpers
│   ├── test/                # Automated regression + security fixture tests
│   ├── Dockerfile
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/             # API client
│   │   ├── components/      # Reusable UI components
│   │   ├── context/         # Auth + theme state
│   │   └── pages/           # Landing, Auth, Dashboard, Results, History
│   ├── public/              # Cloudflare Pages SPA redirects
│   ├── package.json
│   └── vite.config.js
├── docs/
│   └── ARCHITECTURE.md
└── render.yaml
```

---

## 🛠️ Tech Stack

### Frontend

| Technology | Version | Purpose |
|---|---:|---|
| **React** | 18.3.1 | Component-based UI |
| **React Router DOM** | 6.25.1 | Client-side routing and protected routes |
| **Axios** | 1.7.2 | HTTP/API client |
| **Recharts** | 2.12.7 | Score/history charts |
| **Lucide React** | 0.400.0 | UI icons |
| **Tailwind CSS** | 3.4.6 | Responsive styling and design system |
| **Vite** | 5.3.3 | Frontend build tool |

### Backend

| Technology | Version | Purpose |
|---|---:|---|
| **Node.js** | 18+ | Runtime |
| **Express.js** | 4.19.2 | REST API framework |
| **Mongoose** | 8.5.0 | MongoDB ODM |
| **JWT** | 9.0.2 | Authentication tokens |
| **bcryptjs** | 2.4.3 | Password hashing |
| **Helmet** | 7.1.0 | HTTP security headers |
| **express-rate-limit** | 7.3.1 | Abuse/rate protection |
| **Multer** | 1.4.5-lts.1 | Project ZIP upload |
| **adm-zip** | 0.5.14 | ZIP extraction |
| **axios** | 1.7.2 | External API requests |
| **pdfkit** | 0.15.0 | PDF report generation |
| **simple-git** | 3.25.0 | Git repository handling |

### Security tooling

| Tool | Role |
|---|---|
| **npm audit** | Dependency vulnerability detection |
| **Semgrep** | Static source-code security analysis |
| **Custom regex/pattern scanner** | Secret detection |
| **Heuristic scanner** | Selected application-security pattern checks |

---

## 🔐 Security Controls

SecureDev itself also applies security controls to its own API and user data.

| Control | Implementation |
|---|---|
| **Authentication** | JWT access + refresh tokens |
| **Password storage** | bcrypt hashing |
| **Rate limiting** | Express rate limiter on API/auth traffic |
| **HTTP hardening** | Helmet security headers |
| **Input validation** | Express validators on request data |
| **CORS** | Restricted frontend origin configuration |
| **Token encryption** | GitHub token encryption at rest using a dedicated key |
| **Upload limits** | 25 MB maximum project upload |
| **ZIP safety** | Zip-slip protection during extraction |
| **Ephemeral workspaces** | Temporary scan files cleaned after scan |

> ⚠️ Keep all real credentials and encryption keys in environment variables. Never commit production secrets to Git.

---

## 📄 PDF Reporting

SecureDev produces a structured security report designed for both developers and non-technical readers.

### Report includes

- Executive security summary
- Overall score and risk level
- Security-area breakdown and weights
- Scanner coverage/status
- Severity distribution
- Detailed Critical/High findings
- Medium/Low findings
- Plain-language meaning of issues
- Why an issue matters
- Recommended remediation actions
- Methodology and assessment limitations

The report is generated server-side with PDFKit and uses controlled page layouts to avoid text overlap and unnecessary blank pages.

---

## 🧪 Testing

The backend includes automated regression tests covering the core security pipeline.

Current tests include:

- Finding normalization and deduplication
- Scan scoring behavior
- Secret-scanner patterns and hidden `.env.*` files
- npm audit parsing
- Semgrep parsing/classification
- Controlled vulnerable MERN fixture scanning
- Security heuristics
- PDF report generation

GitHub Actions runs the backend regression suite on pushes/pull requests.

---

## 🚀 Deployment

### Current deployment model

| Component | Platform | Purpose |
|---|---|---|
| **Frontend** | Cloudflare Pages | React/Vite production frontend |
| **Backend** | Render | Node/Express API + security scanning |
| **Database** | MongoDB Atlas | Persistent users, projects and scan results |

### Frontend — Cloudflare Pages

Build command:

```bash
npm run build
```

Output directory:

```text
dist
```

Set:

```text
VITE_API_BASE_URL=https://securedev.onrender.com/api
```

### Backend — Render

The backend uses the repository Dockerfile, installs Semgrep, and exposes:

```text
/api/health
```

Production environment variables should be configured in Render rather than committed to the repository.

---

## ⚙️ Environment Variables

Create `backend/.env` locally from `backend/.env.example`.

```env
PORT=5000
NODE_ENV=development
CLIENT_ORIGIN=http://localhost:5173

# MongoDB
MONGODB_URI=mongodb://localhost:27017/securedev

# JWT
JWT_ACCESS_SECRET=replace-with-a-long-random-access-secret
JWT_REFRESH_SECRET=replace-with-a-long-random-refresh-secret
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Password hashing
BCRYPT_SALT_ROUNDS=12

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret
GITHUB_CALLBACK_URL=http://localhost:5000/api/github/callback
GITHUB_TOKEN_ENC_KEY=replace-with-32-byte-base64-key

# Uploads
MAX_UPLOAD_MB=25

# Scanning
SEMGREP_RULESETS=p/javascript,p/nodejs,p/expressjs
SEMGREP_TIMEOUT_MS=120000
NPM_AUDIT_TIMEOUT_MS=60000
```

Generate a valid encryption key with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

---

## ▶️ Getting Started

### Prerequisites

```bash
node -v   # Node.js 18+
npm -v
python3 --version
```

Semgrep is required for source-code scanning when running the backend outside the provided Docker environment.

### 1. Clone the repository

```bash
git clone https://github.com/pranavreddy1721/securedev.git
cd securedev
```

### 2. Start the backend

```bash
cd backend
cp .env.example .env
# edit .env with your local MongoDB/JWT/GitHub settings
npm install
npm run dev
```

### 3. Start the frontend

```bash
cd ../frontend
cp .env.example .env
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

### 4. Production-style Docker run

```bash
cd backend
docker build -t securedev-backend .
docker run --env-file .env -p 10000:10000 securedev-backend
```

---

## 🧭 Typical User Flow

```text
Create account / Sign in
        ↓
Create project or connect repository
        ↓
Upload ZIP / select repository
        ↓
Start security scan
        ↓
Dependency + Secret + Semgrep checks
        ↓
Normalize findings
        ↓
Calculate security assessment
        ↓
Review findings and remediation guidance
        ↓
Download PDF report
```

---

## ⚠️ Limitations

- The heuristic checks for **Insecure File Uploads, Broken Access Control and Sensitive Data Exposure** are lightweight pattern checks, not full static/dataflow analysis.
- There is currently **no Redis/Bull job queue**; scans execute as asynchronous work in the Node process and are intended for student-project scale.
- Uploaded archives and cloned repositories use an **ephemeral temporary filesystem** and are deleted after scanning.
- npm audit parsing targets the npm v7+ JSON output shape.
- Semgrep rulesets are configurable; the project does not bundle a large custom MERN-specific ruleset.
- Automated scanning cannot prove complete application security; important findings still require contextual review.

---

## 🔮 Future Enhancements

- Complete the GitHub repository selection/connection workflow.
- Introduce a Redis/Bull job queue for multi-instance scaling.
- Add broader custom MERN-focused Semgrep rules.
- Expand automated regression and security-fixture coverage.
- Add richer historical scan comparison and project analytics.

---

## 🤝 Contributing

Contributions and improvements are welcome.

```bash
# Create a feature branch
git checkout -b feature/your-feature

# Make changes and commit
git add .
git commit -m "feat: add your feature"

# Push your branch
git push origin feature/your-feature
```

Then open a pull request on GitHub.

---

## 📄 License

Distributed under the MIT License. See the `LICENSE` file for details.

---

<div align="center">

**Built with ❤️ for secure MERN development**

<img src="https://capsule-render.vercel.app/api?type=waving&color=10b981&height=100&section=footer" width="100%" />

</div>