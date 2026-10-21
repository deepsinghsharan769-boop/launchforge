# LaunchForge — self-hostable app builder MVP

A working full-stack starter for a private website/app-building dashboard. Includes server-side login, project CRUD, prompt-to-starter generation, code editing, iframe preview, JSON import/export, and optional deployment integrations.

## Requirements
- Node.js 20+
- npm
- Optional: Vercel or Netlify access token for real deployments
- Optional: OpenAI-compatible API key for AI generation

## Setup
1. Copy `.env.example` to `.env`.
2. Set a long random `SESSION_SECRET`.
3. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` on the server. These are never shipped to the browser.
4. Run:
   ```bash
   npm install
   npm run dev
   ```
5. Open `http://localhost:3000`.

The supplied credentials can be set in the server-side `.env` as:
`ADMIN_USERNAME=sharandeep singh`
`ADMIN_PASSWORD=sharmax in 2028`
For production, change the password and use a secret manager. Do not commit `.env`.

## What works
- HTTP-only session cookie, server-side credential validation, protected API routes.
- Projects saved in local SQLite database.
- Create, edit, duplicate, delete projects.
- HTML/CSS/JS starter generation from prompts (works without an AI key).
- Optional AI generation via an OpenAI-compatible chat-completions endpoint.
- Live preview through a sandboxed iframe.
- Import/export project JSON.
- Deployment request workflow for Vercel and Netlify using server-only API tokens, plus deployment status/log storage.

## Deployment caveats
Real provider deployments require the owner to supply a provider token and connect a provider account. Free-tier limits, build minutes, bandwidth, and custom-domain policies are set by those providers and can change. This starter cannot promise unlimited free hosting. The included deployment adapter sends a static HTML entrypoint to the provider APIs; larger frameworks, build commands, Git repositories, server-side apps, and provider-specific configuration require additional adapters. Test with non-sensitive projects first.

## Production hardening checklist
- Use HTTPS and a secure `SESSION_SECRET`.
- Set `COOKIE_SECURE=true` behind HTTPS.
- Add rate limiting, CSRF protection, audit logging, backups, and account recovery before public multi-user use.
- Deploy the backend to a trusted Node host; never expose provider tokens in frontend code.
- Review generated code before running or publishing it.
