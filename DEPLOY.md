# Deploying Aether so people worldwide can use it

The app must run as **one always-on Node process** (it keeps live SSE connections + in-memory
presence/history/keyring). Use a persistent host — **Render, Railway, or Fly.io** — NOT Vercel
(serverless splits state and kills long connections). All three give free HTTPS, which is
required for the secure session cookie and for microphone/camera access (`getUserMedia`).

Prerequisite: push this repo to GitHub.

```bash
git init && git add -A && git commit -m "Aether messenger"
# create an empty repo on github.com, then:
git remote add origin https://github.com/<you>/aether.git
git branch -M main && git push -u origin main
```

## Option A — Render (simplest, uses render.yaml already in the repo)

1. Go to https://render.com → sign up (free) → **New +** → **Blueprint**.
2. Connect your GitHub and pick the repo. Render reads `render.yaml` and configures everything.
3. Click **Apply**. First build takes ~2–3 min.
4. You get a URL like `https://aether.onrender.com`. Open `…/messenger` and share it.

> Free tier sleeps after ~15 min idle (first request after that is slow). Upgrade the service
> to keep it always-on.

## Option B — Railway (uses the Dockerfile)

1. https://railway.app → **New Project** → **Deploy from GitHub repo** → pick the repo.
2. Railway detects the `Dockerfile`, builds, and assigns a public HTTPS domain.
3. Open `https://<your-app>.up.railway.app/messenger`.

## Option C — Fly.io (uses the Dockerfile)

```bash
# install flyctl, then:
fly launch --now      # detects the Dockerfile; pick a region near your users
# open the printed https URL + /messenger
```

## After deploy — check it

- `https://<your-url>/api/selftest` → `{"ok":true,"passed":16,...}`
- `https://<your-url>/messenger` → log in from two different devices/countries and call/chat.

## What "works" and what doesn't yet

- ✅ Global presence, global chat with history, private DMs, audio/video calls — for everyone
  connected to that one instance, anywhere in the world.
- ⚠️ **Single instance only.** All users share one Node process. That comfortably handles a
  large group; it does not yet shard across regions. To scale to multiple nodes, swap the
  in-memory `lib/rtc/signal-hub.ts` for the Redis Pub/Sub `Bus` in `lib/signaling/relay.ts`
  (each node subscribes to its users' channels; Redis carries cross-node messages). The client
  protocol is unchanged.
- ⚠️ **State is in memory.** A restart clears presence, message history, and session keys
  (everyone re-logs in). For durability, persist history to Postgres/Redis and move signing
  keys to a KMS — see AETHER.md.
- ⚠️ **Calls behind strict NAT** rely on the public OpenRelay TURN baked in. For reliability at
  scale, run your own coturn (`services/coturn.conf`) and set `TURN_HOST` + `TURN_SECRET`.

## Optional environment variables

| Var | Purpose | Default |
|-----|---------|---------|
| `PORT` | Set by the host automatically | 3000 |
| `TURN_HOST` | Your coturn `host:port` for reliable NAT traversal | unset → OpenRelay fallback |
| `TURN_SECRET` | Must equal coturn's `static-auth-secret` | `dev-turn-secret` |
