# Telegram Script-Hosting Bot

A production-oriented Telegram bot that lets approved users upload Python / Node.js
projects (or `.zip` archives), have dependencies installed automatically, and run
the code inside a hardened, disposable Docker sandbox — with live output,
interactive stdin forwarding, a restricted terminal, and an owner admin panel.

All secrets and limits come from the environment. **No credentials are hardcoded.**

---

## Security model (read this first)

This bot executes **arbitrary code submitted by users**. That is inherently
dangerous. The only safe way to run it is with **`EXECUTION_MODE=docker`** (the
default):

* Every process runs in a **disposable container**: read-only root filesystem,
  dropped capabilities (`--cap-drop ALL`), `no-new-privileges`, PID / CPU / memory
  limits, a tiny writable `/tmp` only.
* The **execution phase has the network disabled** — user code cannot reach the
  internet. Dependency installation runs in a *separate* short-lived container
  that is allowed network access just long enough to run `pip` / `npm`, then is
  destroyed.
* Only the user's own workspace folder is mounted inside the container. Host FS,
  SSH keys, the bot token and other secrets are never exposed.
* Containers are auto-terminated on timeout, on stop, and at bot shutdown.
  Orphaned containers from a crash are removed on the next start.

**Unsanboxed local execution (`EXECUTION_MODE=unsandboxed`) runs user code as the
bot's own OS user on the host.** It is only possible when
`ALLOW_UNSANDBOXED_EXECUTION=true`, applies rough rlimit-based limits, and should
only ever be used if you fully trust every user of the bot. Do not use it for
public bots.

> **Render / PaaS warning:** Docker sandboxing requires Docker-in-Docker or a
> host with the Docker daemon available. Many Render plans (and other PaaS) do
> not support this. If your platform cannot run Docker, do **not** switch to
> unsandboxed mode for public users — instead run the bot on a dedicated worker /
> VPS that provides Docker, and keep a separate stateless web tier.

---

## Feature summary

| Feature | Notes |
|---|---|
| `/start` | Channel-membership gate (`CHANNEL_USERNAME`) with inline join + check button |
| Access control | New users are **pending**; owner (re)approves / bans / unbans from inline buttons |
| Upload | `.py`, `.js`, `.zip`; sanitized filenames; traversal & zip-bomb protection |
| Auto pip downloader | `requirements.txt` → `pip install --target /venv`; `package.json` → `npm install --ignore-scripts`, both **inside the sandbox**, never globally |
| Sandboxed execution | Docker (default), network-off run phase, resource limits, auto cleanup |
| Process manager | Registry persisted in `bot_data.json`; per-user + global limits; only owner can stop others' processes |
| Live output | One Telegram message per running process, updated every `LIVE_UPDATE_SECONDS` |
| Interactive stdin | Auto-detects a program waiting for input and forwards the user's next message; times out & closes stdin |
| Restricted terminal | Allowlist: `pwd ls cd cat head tail mkdir cp mv rm`; no shell operators; paths clamped to the workspace |
| Admin panel | User list, pending requests, running processes (stop/kill), statistics, banned users |
| Persistence | Atomic writes to `bot_data.json`; corruption-safe reload |
| Health server | Flask on `0.0.0.0:$PORT` exposing `/`, `/api/`, `/api/healthz` |

---

## Project layout

```
.
├── bot.py              # complete bot (single file, ~2800 lines)
├── requirements.txt
├── .env.example        # config template (copy to .env)
├── .env                # real secrets — git-ignored, NEVER commit
├── .gitignore
├── README.md
└── data/               # created at runtime (git-ignored)
    ├── bot_data.json   # users / projects / process registry (atomic)
    ├── users/<tg_id>/<project_id>/   # uploaded workspaces
    ├── venvs/<project_id>/           # pip targets / npm cache (per project)
    └── logs/<proc_id>.log            # per-process stdout+stderr
```

---

## Setup

### 1. Create the bot and get a token

1. Talk to [@BotFather](https://t.me/BotFather) on Telegram.
2. `/newbot` → choose a name and username → copy the HTTP API token.

### 2. Find your owner/admin chat ID

Send any message to your bot, then call:

```bash
curl "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
```

The `from.id` in the JSON is your numeric chat ID. Put it in `OWNER_ID`.

### 3. Channel configuration

* Create (or use) a Telegram channel. Make the bot an **administrator** of the
  channel (it needs permission to read member status).
* Set `CHANNEL_USERNAME=@yourchannel`.
* If you want to skip the channel gate entirely, leave `CHANNEL_USERNAME` empty.

### 4. Install and configure

```bash
git clone <your-repo> && cd <your-repo>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env: BOT_TOKEN, OWNER_ID, CHANNEL_USERNAME, limits, etc.
```

### 5. Docker setup (required for sandboxing)

Install Docker (Community Edition) on the host and make sure the daemon is
running:

```bash
docker --version
docker run --rm hello-world   # sanity check
```

Pull the runtime images once (they will also be pulled automatically on first use):

```bash
docker pull python:3.11-slim
docker pull node:20-slim
```

### 6. Start the bot

```bash
source .venv/bin/activate
python bot.py
```

The health server becomes available at `http://0.0.0.0:8080/api/healthz` and the
bot starts polling immediately.

---

## Environment variables

See `.env.example` for the full annotated list. Key ones:

| Variable | Default | Purpose |
|---|---|---|
| `BOT_TOKEN` | *(required)* | Telegram bot token |
| `OWNER_ID` | *(required)* | Admin numeric chat ID; bypasses approval, owns Admin Panel |
| `CHANNEL_USERNAME` | *(empty = off)* | Channel users must join (`@name`) |
| `PORT` | `8080` | Health server port |
| `BASE_DIR` | `./data` | Persistent state root |
| `MAX_UPLOAD_MB` / `MAX_ARCHIVE_MB` / `MAX_EXTRACTED_MB` | 20 / 50 / 200 | Upload, archive and unzipped-size caps |
| `MAX_ARCHIVE_ENTRIES` | 500 | Zip entry count cap |
| `MAX_PROCESSES_PER_USER` | 2 | Concurrent processes per user |
| `MAX_GLOBAL_PROCESSES` | 10 | Concurrent processes bot-wide |
| `EXECUTION_TIMEOUT` | 120 | Per-process time limit (seconds) |
| `MAX_LOG_BYTES` | 262144 | Per-process log cap (oldest bytes dropped) |
| `LIVE_UPDATE_SECONDS` | 3 | Live log refresh interval |
| `EXECUTION_MODE` | `docker` | `docker` (safe) or `unsandboxed` (unsafe) |
| `ALLOW_UNSANDBOXED_EXECUTION` | `false` | Must be `true` to enable unsandboxed mode |
| `DOCKER_IMAGE` / `NODE_DOCKER_IMAGE` | `python:3.11-slim` / `node:20-slim` | Runtime images |
| `DOCKER_CPUS` / `DOCKER_MEMORY` / `DOCKER_PIDS` | 1.0 / 256m / 128 | Container resource limits |
| `DOCKER_NETWORK_DISABLED` | `true` | Disable network for the run phase |
| `STDIN_TIMEOUT_SECONDS` | 120 | How long to wait for user input before EOF |
| `INPUT_WAIT_DETECT_SECONDS` | 8 | Idle time before assuming the program wants input |

---

## Usage

* **New user** → `/start` → join the channel → tap **I Joined** → request goes to
  the owner → owner taps **Approve**.
* **Upload** → send a `.py`, `.js` or `.zip`. Dependencies are installed
  automatically (`requirements.txt` / `package.json`), then press **Run**.
  Entrypoint detection: `main.py` → `index.js` → `package.json.main` → exactly one
  source file.
* **Terminal** → menu → 💻 Terminal; commands run with `cwd` = your workspace.
* **Live logs** → menu → 📝 View Logs → tap a process.
* **Interactive programs** → when the program waits for input the bot asks you;
  reply with a plain message (works for `input()`, `readline`, `process.stdin`…).
* **Admin** → 👑 Admin Panel (owner only): users, requests, running scripts,
  stats, banned list.
* **Owner stats** → send `/stats` for a quick snapshot (users by status, projects,
  active processes) read from `bot_data.json`.

---

## Operational notes / limitations

* **Entrypoint**: uploads with no `main.py`/`index.js` and more than one source
  file are rejected — name your entry file explicitly.
* **Stdin detection is heuristic**: a long-running silent computation may be
  mistaken for a program waiting for input; the prompt is harmless and can be
  dismissed with `/cancel_input`.
* **Python deps** are installed with `pip install --target` into a per-project
  volume (`/venv`) and re-used across runs (a marker file skips reinstalls).
  Packages that rely on unusual `site-packages` behaviour may need a manual
  note; standard packages work fine.
* **Node deps** are installed with `--ignore-scripts` (npm lifecycle scripts are
  never executed — this blocks a common supply-chain attack vector). Projects
  that *require* build scripts (`node-gyp`, postinstall) will fail; that is
  intentional.
* **Install phase has network**: the install container is allowed to reach PyPI /
  npm; it is destroyed immediately after and never runs user code.
* **Log rotation** keeps only the most recent `MAX_LOG_BYTES` per process.
* **Process registry** is capped at `MAX_STORED_PROCESSES_PER_USER` records.

---

## Deploying on Linux (systemd)

1. Install Docker, create a `bot` system user with access to the Docker socket or
   configure a dedicated Docker host.
2. Place the repo under `/opt/script-bot`, create `.env`, install deps into a venv.
3. Create `/etc/systemd/system/script-bot.service`:

```ini
[Unit]
Description=Telegram Script-Hosting Bot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=bot
WorkingDirectory=/opt/script-bot
ExecStart=/opt/script-bot/.venv/bin/python /opt/script-bot/bot.py
Restart=always
RestartSec=5
EnvironmentFile=/opt/script-bot/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now script-bot
curl http://127.0.0.1:8080/api/healthz
```

Point a reverse proxy or a platform TCP health check at the health endpoint.

## Deploying on Render (and similar PaaS)

* Render's free/starter web services usually run containers **without** a Docker
  daemon, so `EXECUTION_MODE=docker` will not work there. Options:
  1. Use a Render **Docker** service on a plan that provides Docker-in-Docker
     (check current plan features), or
  2. Keep the bot on a dedicated VPS/worker that has Docker, and use Render only
     for non-executing web tiers.
* **Never** enable `ALLOW_UNSANDBOXED_EXECUTION=true` to work around a missing
  Docker daemon if the bot accepts uploads from the public.

---

## Health check

`GET /api/healthz` → `{"status":"ok","service":"telegram-bot"}` (also `/` and
`/api/`). No secrets are exposed by these endpoints.

---

## License

Use at your own risk. You are responsible for securing your deployment and for
what your users run through it.
