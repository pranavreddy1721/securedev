<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=10b981&height=200&section=header&text=SecureDev&fontSize=58&fontColor=ffffff&fontAlignY=38&desc=Scan%20%E2%80%A2%20Assess%20%E2%80%A2%20Secure&descAlignY=58&descSize=20&animation=fadeIn" width="100%" />

<br/>

<p>
  <img src="https://img.shields.io/badge/React-18.3.1-61DAFB?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Express-4.19-000000?style=for-the-badge&logo=express&logoColor=white" />
  <img src="https://img.shields.io/badge/MongoDB-8-47A248?style=for-the-badge&logo=mongodb&logoColor=white" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white" />
</p>
<p>
  <img src="https://img.shields.io/badge/Semgrep-Static%20Analysis-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/npm%20audit-Dependency%20Security-CB3837?style=for-the-badge&logo=npm&logoColor=white" />
  <img src="https://img.shields.io/badge/GitHub-OAuth%20Import-181717?style=for-the-badge&logo=github&logoColor=white" />
  <img src="https://img.shields.io/badge/PDF-Reports-B91C1C?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" />
</p>

<br/>

> **SecureDev is a full-stack security assessment platform for developer projects.**
> Upload a project or connect a public GitHub repository, run multiple security checks, calculate a weighted security score, review findings, and export a professional PDF report.

<br/>

[📖 GitHub OAuth Setup](docs/GITHUB_SETUP.md) &nbsp;•&nbsp; [🐛 Issues](https://github.com/pranavreddy1721/securedev/issues) &nbsp;•&nbsp; [🚀 Repository](https://github.com/pranavreddy1721/securedev)

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🔄 How It Works](#-how-it-works)
- [🔎 Security Engines](#-security-engines)
- [🧮 Scoring Model](#-scoring-model)
- [🖥️ Screenshots](#️-screenshots)
- [🔗 GitHub Integration](#-github-integration)
- [🛠️ Technology Stack](#️-technology-stack)
- [🗂️ Project Structure](#️-project-structure)
- [⚙️ Environment Variables](#️-environment-variables)
- [🚀 Getting Started](#-getting-started)
- [🧪 Testing & CI](#-testing--ci)
- [🔐 Security Design](#-security-design)
- [📄 PDF Reports](#-pdf-reports)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 Authentication
- Account registration and sign in
- Short-lived access tokens with refresh-token flow
- Protected workspace and scan routes
- Password hashing with bcrypt
- Logout and session cleanup

</td>
<td width="50%">

### 🗂️ Project Workspace
- Project portfolio with latest score
- ZIP upload up to the configured limit
- Public GitHub repository selection
- Scan history per project
- Delete project and related scan history

</td>
</tr>
<tr>
<td width="50%">

### 🔎 Security Assessment
- Dependency security through `npm audit`
- Secrets detection with dedicated patterns
- Semgrep-based application security checks
- Additional heuristic checks
- Finding normalization and deduplication

</td>
<td width="50%">

### 📊 Scoring & Reporting
- Weighted score out of 100
- Risk-band calculation
- Category-wise sub-scores
- Critical/high issue summary
- Downloadable PDF assessment report

</td>
</tr>
<tr>
<td width="50%">

### 🔗 GitHub Workflow
- OAuth connection with `public_repo` scope
- Connected-account status
- Public repository search and pagination
- Repository selection from the workspace
- Secure token encryption at rest

</td>
<td width="50%">

### 🎨 Developer Experience
- Responsive React interface
- Light/dark appearance support
- Clear loading and error states
- Security-focused dashboard cards
- Clean assessment and report views

</td>
</tr>
</table>

> **Scope note:** The AI Explain/Fix feature was removed from the current SecureDev scope. The product focuses on deterministic security scanning, scoring, findings, and reporting.

---

## 🔄 How It Works

```text
┌──────────────────────┐
│       Sign In        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Security Workspace │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Upload ZIP / Connect │
│    GitHub Project    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Launch New Scan    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Security Engines    │
│ npm audit + secrets  │
│ Semgrep + heuristics │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Normalize Findings   │
│ & Calculate Score    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Results + Risk Band  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    Download PDF      │
└──────────────────────┘
```

The scan orchestrator runs the core engines concurrently. Findings are normalized and deduplicated before scoring. If a core engine fails, the scan is marked incomplete and a comprehensive score is not generated.

---

## 🔎 Security Engines

| Engine | Purpose | Output |
|---|---|---|
| **npm audit** | Reviews dependency vulnerabilities for Node.js projects | Dependency findings |
| **Secret Scanner** | Detects credentials and secret-like values using patterns | Secret findings |
| **Semgrep** | Static analysis using JavaScript/Node/Express rulesets | Application-security findings |
| **Heuristic Scanner** | Detects additional risky code/configuration patterns | Supplementary findings |
| **Finding Normalizer** | Normalizes and deduplicates engine output | Unified findings |

### Supported assessment areas

| Security Area | Weight |
|---|---:|
| **Dependency Security** | 30% |
| **Authentication** | 20% |
| **Secrets Detection** | 20% |
| **Application Security** | 20% |
| **Configuration** | 10% |
| **Total** | **100%** |

---

## 🧮 Scoring Model

SecureDev calculates a final score from the five weighted security areas:

```text
Dependency Security     30%
Authentication          20%
Secrets Detection       20%
Application Security    20%
Configuration           10%
                        ───
                        100%
```

The results interface presents the final score, risk band, issue counts, engine completion status, and each category's sub-score.

### Example assessment

```text
Overall Score       62 / 100
Risk Level          Medium Risk
Total Issues        9
Critical / High     3
Checks Completed    3 / 3
Assessment          Complete
```

Example category scores:

| Category | Score | Weight |
|---|---:|---:|
| Dependency Security | 13 / 100 | 30% |
| Authentication | 100 / 100 | 20% |
| Secrets Detection | 100 / 100 | 20% |
| Application Security | 39 / 100 | 20% |
| Configuration | 100 / 100 | 10% |

---

## 🖥️ Screenshots

### 🔐 Sign In

![SecureDev Sign In](docs/screenshots/login.png)

### 🛡️ Security Workspace

![SecureDev Workspace](docs/screenshots/workspace.png)

### 📊 Scan Results

![SecureDev Scan Results](docs/screenshots/scan-results.png)

---

## 📈 Workspace Dashboard

The workspace summarizes the user's security portfolio with four primary metrics:

| Metric | Meaning |
|---|---|
| **Projects** | Total projects tracked |
| **Scored Projects** | Projects with completed assessments |
| **Average Score** | Average score across scored projects |
| **Attention Needed** | Projects below the configured 60-point threshold |

Each project card exposes the latest score, assessment interpretation, scan-again action, result view, scan history, and delete action.

---

## 🔗 GitHub Integration

SecureDev's GitHub integration is now implemented end-to-end:

1. User opens **New security scan → GitHub repo**.
2. SecureDev checks the current GitHub connection.
3. If disconnected, the user starts GitHub OAuth.
4. OAuth uses the limited `public_repo` scope.
5. A short-lived state value protects the callback against CSRF.
6. The GitHub access token is encrypted before being stored.
7. Public repositories are listed with search and pagination.
8. The selected repository is stored as a GitHub project source.
9. The backend constructs the clone URL itself instead of trusting a client-supplied URL.
10. The repository is shallow-cloned for scanning and `.git` is removed before scanners run.

### Configure GitHub OAuth

See the complete setup guide:

**[`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md)**

The code is ready for the OAuth connection, but the GitHub OAuth application's Client ID/Secret and token-encryption key must be supplied as environment variables in the deployment environment.

---

## 🛠️ Technology Stack

### Frontend

| Technology | Purpose |
|---|---|
| **React 18** | Component-based UI |
| **Vite 5** | Development server and production build |
| **React Router 6** | Client-side routing and protected pages |
| **Tailwind CSS 3** | Responsive utility-first styling |
| **Axios** | API requests and token refresh handling |
| **Lucide React** | Interface icons |
| **Recharts** | Data visualization support |

### Backend

| Technology | Purpose |
|---|---|
| **Node.js** | Runtime |
| **Express 4** | REST API |
| **Mongoose 8** | MongoDB ODM |
| **JWT** | Access/refresh authentication |
| **bcryptjs** | Password/token hashing |
| **Multer** | ZIP upload handling |
| **Adm-Zip** | Safe ZIP extraction |
| **Simple-Git** | GitHub repository cloning |
| **Axios** | GitHub API communication |
| **PDFKit** | PDF report generation |
| **Helmet** | HTTP security headers |
| **express-rate-limit** | Request throttling |

### Security tooling

- `npm audit`
- Semgrep (`p/javascript`, `p/nodejs`, `p/expressjs` by default)
- Custom secret patterns
- Heuristic security checks
- Finding normalization/deduplication

### Infrastructure

- **MongoDB / MongoDB Atlas** for persistent application data
- **Render** configuration included for the backend service
- Static Vite frontend deployment supported through the generated production build

---

## 🗂️ Project Structure

```text
securedev/
├── .github/
│   └── workflows/
│       └── backend-tests.yml
│
├── backend/
│   ├── src/
│   │   ├── config/
│   │   ├── controllers/
│   │   ├── middleware/
│   │   ├── models/
│   │   ├── orchestrator/
│   │   ├── reports/
│   │   ├── routes/
│   │   ├── scanners/
│   │   ├── scoring/
│   │   └── utils/
│   ├── test/
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── context/
│   │   └── pages/
│   ├── package.json
│   └── vite.config.js
│
├── docs/
│   ├── GITHUB_SETUP.md
│   └── screenshots/
│
├── render.yaml
├── .gitignore
└── README.md
```

---

## ⚙️ Environment Variables

### Backend

Create `backend/.env` from `backend/.env.example`:

```env
PORT=5000
NODE_ENV=development
CLIENT_ORIGIN=http://localhost:5173

MONGODB_URI=mongodb://localhost:27017/securedev

JWT_ACCESS_SECRET=replace-with-a-long-random-access-secret
JWT_REFRESH_SECRET=replace-with-a-long-random-refresh-secret
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
BCRYPT_SALT_ROUNDS=12

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret
GITHUB_CALLBACK_URL=http://localhost:5000/api/github/callback
GITHUB_TOKEN_ENC_KEY=your-32-byte-base64-key

MAX_UPLOAD_MB=25
SEMGREP_RULESETS=p/javascript,p/nodejs,p/expressjs
SEMGREP_TIMEOUT_MS=120000
NPM_AUDIT_TIMEOUT_MS=60000
```

### Frontend

Create `frontend/.env` when you want to override the API URL:

```env
VITE_API_BASE_URL=http://localhost:5000/api
```

> ⚠️ Never commit real secrets. The repository includes `.env.example` files for configuration templates.

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18 or newer
- npm 9 or newer
- MongoDB local instance or MongoDB Atlas
- Python/pip if Semgrep is not already available in the backend environment
- Git if GitHub repository scanning is enabled

### 1. Clone the repository

```bash
git clone https://github.com/pranavreddy1721/securedev.git
cd securedev
```

### 2. Install backend dependencies

```bash
cd backend
npm install
```

### 3. Configure backend environment

```bash
cp .env.example .env
```

Fill in the MongoDB and JWT values. For GitHub scanning, also configure the GitHub OAuth variables described in [`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md).

### 4. Start the backend

```bash
cd backend
npm run dev
```

The API runs on `http://localhost:5000` by default.

Health check:

```text
GET http://localhost:5000/api/health
```

### 5. Install and start the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server normally runs on `http://localhost:5173`.

### 6. Production build

```bash
cd frontend
npm run build
```

---

## 🧪 Testing & CI

### Backend tests

```bash
cd backend
npm test
```

The test suite covers scoring, finding normalization, PDF generation, secret scanning, scan parsing, security fixtures, and security-boundary cases.

### Frontend build check

```bash
cd frontend
npm ci
npm run build
```

### GitHub Actions

The repository CI workflow runs:

- Backend dependency installation and automated tests
- Frontend dependency installation and production build

This provides a regression check for both halves of the application on pushes and pull requests targeting `main`.

---

## 🔐 Security Design

SecureDev itself applies security controls because it handles source code and GitHub credentials.

| Control | Implementation |
|---|---|
| **Password hashing** | bcryptjs |
| **Access control** | JWT-protected API routes |
| **Rate limiting** | express-rate-limit |
| **HTTP headers** | Helmet |
| **CORS** | Explicit configured origins |
| **ZIP extraction** | Zip-slip/path traversal validation |
| **GitHub OAuth state** | Random, short-lived, single-use state |
| **GitHub token storage** | AES-256-GCM encryption at rest |
| **Clone target validation** | GitHub HTTPS URLs only |
| **Client URL trust** | Backend constructs GitHub clone URL |
| **Git metadata** | `.git` removed after clone |
| **Temporary scan data** | Cleanup after scan completion/failure |
| **Secrets** | Environment variables, never source-controlled |

### Important security boundary

SecureDev is a security assessment tool, not a guarantee that a project is secure. Results should be reviewed with the underlying findings and project context.

---

## 📄 PDF Reports

Completed scans can be exported through the scan-results interface. The backend generates the PDF before sending the response so report-generation failures can be handled cleanly by the API.

A report contains the assessment summary, score/risk information, category breakdown, findings, and scan metadata.

---

## 🤝 Contributing

```bash
git checkout -b feature/your-change
# make and test your changes
git add .
git commit -m "Describe the change"
git push origin feature/your-change
```

Open a pull request against `main`. Keep secrets out of commits and update the documentation when changing the assessment workflow or scoring model.

---

## 📄 License

The repository does not currently include a `LICENSE` file. Add the project's chosen license before publishing an explicit license statement here.

---

<div align="center">

**Built with ❤️ for better software security.**

<img src="https://capsule-render.vercel.app/api?type=waving&color=10b981&height=100&section=footer" width="100%" />

</div>
