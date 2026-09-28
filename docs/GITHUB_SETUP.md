# SecureDev GitHub Connection Setup

SecureDev supports connecting a user's GitHub account so the user can select a **public repository** and scan it from the workspace.

The AI explain/fix feature is intentionally not part of the current SecureDev implementation.

## 1. Create a GitHub OAuth App

In the GitHub account that will own the OAuth application, create an OAuth App with:

- **Application name:** SecureDev
- **Homepage URL:** `https://securedev.pages.dev`
- **Authorization callback URL:** `https://securedev.onrender.com/api/github/callback`

The application only requests the `public_repo` scope. Do not configure the product to request the broader `repo` scope.

Copy the generated **Client ID** and **Client Secret**.

## 2. Generate the token-encryption key

SecureDev encrypts the GitHub access token before storing it in MongoDB.

Generate a fresh 32-byte base64 key:

```bash
openssl rand -base64 32
```

Do not commit this value to GitHub.

## 3. Configure the backend

For local development, copy `backend/.env.example` to `backend/.env` and set:

```env
CLIENT_ORIGIN=http://localhost:5173
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
GITHUB_CALLBACK_URL=http://localhost:5000/api/github/callback
GITHUB_TOKEN_ENC_KEY=your-32-byte-base64-key
```

The remaining MongoDB and JWT variables are also required by the backend.

## 4. Configure Render

The repository already declares the GitHub environment variables in `render.yaml` as secret (`sync: false`) values.

In the Render backend service, set:

```text
CLIENT_ORIGIN=https://securedev.pages.dev
GITHUB_CLIENT_ID=<GitHub OAuth Client ID>
GITHUB_CLIENT_SECRET=<GitHub OAuth Client Secret>
GITHUB_CALLBACK_URL=https://securedev.onrender.com/api/github/callback
GITHUB_TOKEN_ENC_KEY=<fresh 32-byte base64 key>
```

Redeploy the backend after changing these values.

## 5. Configure the frontend

For a local frontend, `VITE_API_BASE_URL` should point to the local backend:

```env
VITE_API_BASE_URL=http://localhost:5000/api
```

The production frontend can use:

```env
VITE_API_BASE_URL=https://securedev.onrender.com/api
```

## 6. User flow

1. Sign in to SecureDev.
2. Open **New security scan**.
3. Select **GitHub repo**.
4. If GitHub is not connected, select **Connect GitHub**.
5. Authorize the `public_repo` permission.
6. GitHub redirects back to SecureDev.
7. SecureDev reopens the project dialog and shows the connected GitHub username.
8. Search/select a repository and choose **Add repository & scan**.
9. SecureDev clones the selected repository using the encrypted OAuth token.
10. The `.git` directory is removed before security scanners run.

## Security notes

- OAuth state is random, short-lived, single-use, and tied to the SecureDev user.
- GitHub access tokens are encrypted at rest with AES-256-GCM.
- Client-supplied clone URLs are ignored; the backend constructs the clone URL from a validated `owner/repository` value.
- Only GitHub HTTPS clone targets are accepted.
- GitHub repository metadata is not stored as a token-bearing URL.
- The scanner does not need Git history, so `.git` is removed after cloning.
- Never commit `.env`, GitHub Client Secrets, OAuth tokens, or `GITHUB_TOKEN_ENC_KEY`.
