# Email Security Analyser

A client-side web application for analysing email headers and reading EML/MSG files. All file processing happens locally in your browser — email contents and attachments are never uploaded to any server.

**Live:** [eml.insecure.co.nz](https://eml.insecure.co.nz)

---

## What it does

### Header Analyser
Paste raw email headers to check:
- **SPF** — whether the sending server is authorised to send on behalf of the domain
- **DKIM** — whether the message signature is valid and the content hasn't been altered
- **DMARC** — whether the message satisfies the domain's authentication policy
- **ARC** — whether a forwarded message has a valid authentication chain
- **Spam score** — X-Spam-Score/X-Spam-Status header parsing
- **Routing** — the path the email took through mail servers, hop by hop
- **Overall verdict** — Good / Caution / Bad based on combined results

To get headers from Gmail: open the email → three-dot menu → *Show original*. In Outlook: File → Properties → Internet headers.

### EML / MSG Reader
Upload a `.eml` or `.msg` file to:
- View From, To, Subject, Date
- Read the email body (HTML rendered safely, plain text fallback)
- Download attachments (dangerous file types are flagged before download)
- Inspect all raw headers
- Auto-populate the Header Analyser tab for immediate analysis

`.eml` is the standard format exported from most mail clients. `.msg` is the Outlook format — this tool lets you open MSG files on any platform including Mac, where Outlook can't open them natively.

---

## Technologies

| Package | Purpose |
|---|---|
| React 18 + Vite | UI framework and build tooling |
| Tailwind CSS (CDN) | Styling |
| postal-mime | EML file parsing |
| @kenjiuno/msgreader | MSG file parsing |
| DOMPurify | HTML sanitisation before rendering email bodies |
| Lucide React | Icons |

---

## Deployment (Cloudflare Pages via GitHub)

This is how the live site is deployed — Cloudflare Pages builds and deploys automatically on every push to the `main` branch.

### First-time setup

1. Push this repository to GitHub
2. Log in to the [Cloudflare Pages dashboard](https://pages.cloudflare.com)
3. Click **Create a project** → **Connect to Git**
4. Select your GitHub repository
5. Set the following build settings:

| Setting | Value |
|---|---|
| Build command | `npm run build` |
| Build output directory | `dist` |
| Node.js version | `18` or higher (set in Environment Variables as `NODE_VERSION = 18`) |

6. Under **Environment Variables**, add:

| Variable | Value |
|---|---|
| `VITE_DISCORD_WEBHOOK_URL` | Your Discord webhook URL (see Telemetry section below) |

7. Click **Save and Deploy**

From this point on, every push to `main` triggers a new build and deployment automatically. No manual steps required.

### Security headers

The `public/_headers` file configures Cloudflare Pages to serve the following HTTP security headers on every response:

- `Content-Security-Policy` — restricts what the page can load and connect to
- `X-Frame-Options: DENY` — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME type sniffing
- `Referrer-Policy: same-origin`
- `Permissions-Policy` — disables camera, microphone, geolocation and payment APIs

This file is picked up automatically by Cloudflare Pages from the `dist/` output — no additional configuration required.

---

## Local development

### Prerequisites
- Node.js 18+
- npm 9+

### Setup

```bash
git clone https://github.com/SethBodine/EmailReader.git
cd EmailReader
npm install
```

Create a `.env.local` file if you want telemetry working locally:

```
VITE_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook
```

```bash
npm run dev
```

Visit http://localhost:5173

### Production build

```bash
npm run build
```

Output is in `dist/`. The `_headers` file is automatically copied from `public/` into `dist/` during the build.

---

## Telemetry

When a user analyses headers, the following metadata is sent to a Discord webhook:

| Field | Detail |
|---|---|
| IP address | Retrieved from Cloudflare's own edge (`cloudflare.com/cdn-cgi/trace`) — no third-party service |
| File type | EML, MSG, or Manual |
| From address | The sender address from the analysed email |
| To address | The recipient address from the analysed email |
| SPF / DKIM / DMARC / ARC | Pass / Fail / Warning / None |
| Spam score | Level and numeric score |
| Overall verdict | Good / Caution / Bad |

**Email body content and attachment data are never captured.**

Telemetry is only active when `VITE_DISCORD_WEBHOOK_URL` is set. If the variable is not set, no data is sent. The footer of the application discloses to users that analysis metadata is logged.

Telemetry is used solely to understand if and when the tool is being used. Data is not shared or sold.

---

## Project structure

```
EmailReader/
├── public/
│   └── _headers          # Cloudflare Pages HTTP security headers
├── src/
│   ├── App.jsx            # Main application — all logic and UI
│   ├── main.jsx           # React entry point
│   └── index.css          # Global styles
├── index.html             # HTML shell (loads Tailwind CDN)
├── package.json           # Dependencies
├── vite.config.js         # Vite build configuration
└── .gitignore
```

---

## Browser compatibility

Chrome/Edge 90+, Firefox 88+, Safari 14+, modern mobile browsers.

---

## Acknowledgments

- [postal-mime](https://github.com/postalsys/postal-mime) — EML parsing
- [MSGReader](https://github.com/kenjiuno/MSGReader.js) — MSG file support
- [DOMPurify](https://github.com/cure53/DOMPurify) — HTML sanitisation
- [Tailwind CSS](https://tailwindcss.com/) — Styling
- [Lucide](https://lucide.dev/) — Icons

---

## License

MIT — see LICENSE file.
