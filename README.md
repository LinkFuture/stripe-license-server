# stripe-license-server

Open-source license server for desktop and other client apps. Stripe is the only way a license key is created. A short key activates a machine; the server then returns an Ed25519-signed JWT that the app can check offline until it expires.

The product requirements are in [docs/PRD.md](docs/PRD.md). This repository is a generic service. It is not tied to any one product.

License: MIT, copyright Link Future LLC.

## Architecture

```text
Stripe Payment Link
        |
        | checkout.session.completed
        v
Cloudflare Worker (Hono) ---- D1 (SQLite)
        |                         apps, licenses, activations,
        |                         trials, events, email_codes
        | Ed25519 JWT
        v
@linkfuture/license-client
        |
        | verifies JWT locally with the app's public key
        v
Host application
```

- `server/` is a Cloudflare Worker. Public routes live under `/v1/{app}/`. Stripe posts to `/v1/stripe/webhook`. Operators call `/admin/*` with `Authorization: Bearer $ADMIN_TOKEN`.
- `packages/license-client/` is the npm package `@linkfuture/license-client`. It runs in a trusted Node.js process. It stores the key and the JWT through a storage adapter you provide.
- Each app has its own slug, display name, key prefix, trial length, offline grace period, inactive-device window, reset quota, and Ed25519 key pair. The private key is a Worker secret named `APP_KEY_<SLUG>`. D1 stores only the public key.
- There is no plans table and no manual “issue a key” API. Device limit is `licenses.max_machines`, copied from the Stripe Checkout Session metadata.

### How a purchase becomes a key

1. The buyer pays through a Stripe Payment Link (or a 100% coupon, which completes a $0 Checkout with no PaymentIntent).
2. Stripe sends `checkout.session.completed`.
3. The worker reads `metadata.app` and `metadata.max_machines`, and the email on `customer_details`.
4. If either metadata field is missing or invalid, or the email is missing, it writes a `webhook.error` event and returns 200 so Stripe does not retry forever.
5. Otherwise it creates one license row keyed by `stripe_session_id`. A repeat delivery of the same session does not create a second key.
6. It emails the key from `EMAIL_FROM` (default `info@linkfuture.net`) through the Resend HTTP API. If `RESEND_API_KEY` is unset, it skips the send and logs that fact.

`charge.refunded` (full refund only) and `charge.dispute.created` look up `stripe_payment_intent` and set `status = 'revoked'`, `revoked_at`, and `revoke_reason` (`refund` or `dispute`). A partial refund does not revoke the license. A $0 Checkout has a null payment intent, so there is nothing for a later refund event to find; that is expected.

## Offline verification

The short key is only an activation credential. After a successful `activate` or `validate`, the server returns a JWT:

| Claim | Meaning |
| --- | --- |
| `iss` | `JWT_ISS`, default `license.linkfuture.net` |
| `aud` | App slug |
| `sub` | License id |
| `mid` | Machine hash |
| `max` | `max_machines` |
| `iat`, `exp` | Issued at, and `exp = iat + offline_grace_days` (default 30) |
| `kind` | `license` |

The algorithm is EdDSA (Ed25519). HS256 is not used and is rejected by the client. The email address is not a claim.

On each launch the client checks, in order: signature, `aud` equals its app slug, `mid` equals the local machine hash, and `exp` is still in the future. No network is required for that check. The first activation does require the network.

While online, the app calls `validate` in the background. A revoked license gets no new token. The previous token keeps working until `exp`; after that the client reports `revoked` if a refresh already learned the license was revoked, and stops treating the user as licensed.

Trial registration returns a second JWT (`kind = trial`, `sub = trial:{id}`) whose `exp` is the trial end. The client can verify that offline the same way.

### Machine hash

The server never sees the raw machine id. The client computes:

```text
machine_hash = hex(SHA-256(utf8(appSlug + "\0" + rawMachineId)))
```

The NUL separator keeps two apps on the same computer from producing the same hash, so trials and activations cannot be correlated across apps.

### Trial clock

The trial is stored per `(app, machine_hash)`. Reinstalling does not create a new row. The effective start is the earlier of the server clock and the client’s local install time, so a reinstall or a clock change cannot extend the trial. A future local timestamp is clamped to server time.

If the first launch is offline, the client starts the trial from the local install time it records, and registers with the server later. The server keeps `min(server start, local start)`. The client also ignores a clock that moves backward, so setting the clock back does not restore days that already elapsed.

### Device slots

- Activating a machine that is already on the license refreshes `last_seen_at` and does not consume another slot.
- When `used >= max_machines`, `activate` returns `machine_limit_reached` and the list of machines (name, platform, `last_seen_at`, and whether each one counts).
- `deactivate` removes the current machine.
- `reset-machines` emails a 6-digit code to the buyer, then deletes every activation and activates the machine that confirmed the code. Codes expire in 15 minutes and allow 5 attempts. The quota is per app: `apps.reset_limit` successful resets per license inside `apps.reset_window_days` (defaults 5 and 30). `reset_limit = 0` means unlimited.
- An activation whose `last_seen_at` is older than `apps.inactive_release_days` (default 90, `0` disables the rule) no longer counts toward `max_machines`. The row is kept.

## Schema

Apply `server/migrations/0001_init.sql`. Timestamps are ISO-8601 UTC text.

Per-app columns on `apps` (set on `POST /admin/apps` or `PATCH /admin/apps/{slug}`):

| Column | Default | Meaning |
| --- | --- | --- |
| `trial_days` | 30 | Trial length for a new machine |
| `offline_grace_days` | 30 | License JWT lifetime after each online refresh |
| `inactive_release_days` | 90 | Machines quieter than this no longer count toward `max_machines`. `0` disables the rule |
| `reset_limit` | 5 | Self-service device resets per license in the rolling window. `0` is unlimited |
| `reset_window_days` | 30 | Length of that rolling window |

```sql
CREATE TABLE apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  trial_days INTEGER NOT NULL DEFAULT 30 CHECK (trial_days >= 0),
  offline_grace_days INTEGER NOT NULL DEFAULT 30 CHECK (offline_grace_days >= 0),
  inactive_release_days INTEGER NOT NULL DEFAULT 90 CHECK (inactive_release_days >= 0),
  reset_limit INTEGER NOT NULL DEFAULT 5 CHECK (reset_limit >= 0),
  reset_window_days INTEGER NOT NULL DEFAULT 30 CHECK (reset_window_days >= 1),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  key_hash TEXT NOT NULL UNIQUE,
  key_last4 TEXT NOT NULL,
  key_enc TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE,
  max_machines INTEGER NOT NULL CHECK (max_machines > 0),
  stripe_session_id TEXT NOT NULL UNIQUE,
  stripe_payment_intent TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  revoked_at TEXT,
  revoke_reason TEXT CHECK (revoke_reason IN ('refund', 'dispute', 'admin')),
  email_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_licenses_app_email ON licenses(app_id, email);

CREATE TABLE activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  machine_hash TEXT NOT NULL,
  machine_name TEXT,
  platform TEXT,
  app_version TEXT,
  activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (license_id, machine_hash)
);

CREATE INDEX idx_activations_machine ON activations(machine_hash);

CREATE TABLE trials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  machine_hash TEXT NOT NULL,
  started_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  platform TEXT,
  app_version TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (app_id, machine_hash)
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER REFERENCES apps(id),
  license_id INTEGER REFERENCES licenses(id),
  type TEXT NOT NULL,
  machine_hash TEXT,
  ip TEXT,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_events_license ON events(license_id, created_at);
CREATE INDEX idx_events_app_type ON events(app_id, type, created_at);

CREATE TABLE email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  email TEXT NOT NULL COLLATE NOCASE,
  license_id INTEGER REFERENCES licenses(id),
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('recover', 'reset_machines')),
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_email_codes_lookup ON email_codes(app_id, email, purpose, created_at);

CREATE TABLE rate_limits (
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);
```

`key_hash` is SHA-256 of the canonical key (`PREFIX-XXXXX-XXXXX-XXXXX-XXXXX`). `key_last4` supports admin search. `key_enc` is AES-GCM ciphertext of the key, wrapped by `LICENSE_ENCRYPTION_KEY`, so a recovery email can resend the key. A database copy without that secret does not reveal the key.

Keys use Crockford Base32 (no I, L, O, or U in the random groups). Input is uppercased, whitespace is removed, and in the random groups `I`/`L` become `1` and `O` becomes `0`.

Audit events include `license.issued`, `license.revoked`, `license.recovered`, `activation.created`, `activation.removed`, `activation.validated`, `trial.started`, `trial.adjusted`, `reset.requested`, and `webhook.error`.

## Stripe

1. Create a Payment Link for a one-time price. Do not use subscription mode; subscriptions are out of scope for v1.
2. On that Payment Link, set metadata. Stripe copies Payment Link metadata onto the Checkout Session, which is what the webhook reads.

| Metadata key | Value |
| --- | --- |
| `app` | App slug, for example `myapp` |
| `max_machines` | Positive integer as text, for example `2` |

3. Comp or test keys use the same Payment Link with a 100% coupon. Checkout completes at $0 and usually has no `payment_intent`. The worker still issues a key.
4. In the Stripe Dashboard (test mode first), add a webhook endpoint:

```text
https://<your-worker-host>/v1/stripe/webhook
```

Subscribe to:

- `checkout.session.completed`
- `charge.refunded`
- `charge.dispute.created`

5. Put the endpoint signing secret in `STRIPE_WEBHOOK_SECRET`. The worker verifies `Stripe-Signature` with HMAC-SHA256 over `{timestamp}.{raw body}` and a 5-minute tolerance. Unsigned or stale events are rejected with 400.

`STRIPE_SECRET_KEY` is reserved for a future Stripe API call. v1 only needs the webhook signing secret.

## Deploy

From `server/` after `npm install` at the repo root:

```bash
npx wrangler login
npx wrangler d1 create stripe-license
```

`wrangler d1 create` prints a database UUID. Leave the placeholder `database_id` in `server/wrangler.toml` and do not commit the real id. Publishing a release substitutes the GitHub variable `D1_DATABASE_ID` (see [Continuous deployment](#continuous-deployment)). For a one-off deploy from a laptop, replace the placeholder in your local checkout, run the commands below, and leave that edit uncommitted.

```bash
npx wrangler d1 migrations apply stripe-license --remote
printf '%s' 'a-long-random-admin-token' | npx wrangler secret put ADMIN_TOKEN
printf '%s' 'whsec_...' | npx wrangler secret put STRIPE_WEBHOOK_SECRET
printf '%s' 'sk_live_...' | npx wrangler secret put STRIPE_SECRET_KEY
printf '%s' 're_...' | npx wrangler secret put RESEND_API_KEY
printf '%s' 'a-long-random-encryption-key' | npx wrangler secret put LICENSE_ENCRYPTION_KEY
npx wrangler deploy
```

Register an app (this prints the Ed25519 private key once; it is not written to D1):

```bash
curl -s -X POST "$LICENSE_API_BASE/admin/apps" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug":"myapp","name":"My App","key_prefix":"MYAPP","trial_days":30,"offline_grace_days":30}'
```

Store the printed PKCS8 PEM as the secret for that slug. `myapp` becomes `APP_KEY_MYAPP`:

```bash
npx wrangler secret put APP_KEY_MYAPP
```

Non-secret defaults live in `wrangler.toml` `[vars]`:

- `JWT_ISS` = `license.linkfuture.net`
- `EMAIL_FROM` = `info@linkfuture.net`

Optional rate-limit vars are listed in `server/.dev.vars.example`. Copy that file to `server/.dev.vars` for `wrangler dev`. Never commit `.dev.vars`.

Local database:

```bash
npm run db:migrate:local -w server
```

Verify Resend for the `linkfuture.net` domain (SPF and DKIM) so mail from `info@linkfuture.net` is delivered. Embed each app’s `public_key` in that app’s build. Customers only need the public key.

### Admin CLI

```bash
LICENSE_API_BASE=https://license.example.com ADMIN_TOKEN=... npm run admin -- stats
LICENSE_API_BASE=https://license.example.com ADMIN_TOKEN=... npm run admin -- stats myapp
npm run admin -- licenses myapp
npm run admin -- activations myapp
npm run admin -- revoke 12
npm run admin -- unbind 34
```

`GET /admin/stats` without `app` returns one breakdown per app: license totals, licenses grouped by `max_machines`, activated licenses, distinct buyer emails, machines by platform and app version, machines seen in the last 7 and 30 days, trial totals (running, expired, and trial machine hashes that later appear on an activation), and a 30-day daily trend of `trial.started`, `activation.created`, and `license.issued`.

`GET /admin/licenses` and `GET /admin/activations` filter and paginate (`page`, 50 per page). License rows include `used_machines` and `max_machines`.

Changing `max_machines` on an existing license (there is no self-serve upgrade in v1) is a direct SQL update. App settings such as `trial_days` can be changed with `PATCH /admin/apps/{slug}`.

## Continuous deployment

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `npm ci`, typecheck, lint, and test on every pull request and on every push to `main`. It uses no secrets.

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) runs only when a GitHub Release is published, and when someone starts it with `workflow_dispatch`. It checks out the release tag (or, for a manual run, the ref you select), runs `npm ci` and `npm test`, and deploys only if the tests pass. It does not run on `pull_request`, so a fork pull request cannot receive production credentials.

The deploy job is the only job that sets `environment: production`. Create that environment under **Settings → Environments**. Store the Cloudflare credentials as **Environment secrets** of `production`, not as repository secrets. A repository secret is available to every workflow in the repo. An environment secret is injected only into a job that names that environment, so in this repo only the deploy job can read them. The test job in the deploy workflow does not use the environment and does not receive them.

| Name | Where | Purpose |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | `production` environment secret | Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | `production` environment secret | Cloudflare account id |
| `D1_DATABASE_ID` | `production` environment variable | UUID from `wrangler d1 create stripe-license` |

On the same environment, turn on **Required reviewers** so a release does not deploy until you approve it:

1. Open **Settings → Environments → production**.
2. Under **Deployment protection rules**, check **Required reviewers**.
3. Add the owner (and anyone else who may approve). Up to six reviewers.
4. Save the protection rules.

Publishing a release still starts the workflow. Tests run immediately. The deploy job then stays **Waiting** until a required reviewer approves it on the Actions run page. Approval is also required for a manual `workflow_dispatch` run. Rejecting or leaving it waiting means Wrangler does not run.

The workflow writes `D1_DATABASE_ID` over the placeholder `database_id` in `server/wrangler.toml` on the runner, then uses `cloudflare/wrangler-action` to run `wrangler d1 migrations apply stripe-license --remote` and `wrangler deploy` in `server/`.

Create the API token with these account permissions:

- Workers Scripts: Edit
- D1: Edit
- Account Settings: Read

Worker runtime secrets are not stored in GitHub. Set each one once with `wrangler secret put`: `ADMIN_TOKEN`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `RESEND_API_KEY`, `LICENSE_ENCRYPTION_KEY`, and `APP_KEY_<SLUG>` for every app. Publishing another release does not clear them.

## Client SDK

`@linkfuture/license-client` is for a trusted process that can hold the license key. Configure `appSlug`, the app public key (PEM or JWK), `apiBase`, a storage adapter, and a raw machine-id provider.

```ts
import { LicenseClient } from "@linkfuture/license-client";

const client = new LicenseClient({
  appSlug: "myapp",
  publicKey: process.env.LICENSE_PUBLIC_KEY!,
  apiBase: "https://license.example.com",
  trialDays: 30,
  machineId: async () => readRawMachineId(),
  storage: {
    async get(key) {
      return store.get(key) ?? null;
    },
    async set(key, value) {
      store.set(key, value);
    },
  },
});

const status = await client.getStatus();
// status.state is licensed | trial | trial_expired | unlicensed | revoked

await client.activate("MYAPP-XXXXX-XXXXX-XXXXX-XXXXX");
await client.refreshInBackground();
await client.startTrial();
await client.deactivate();
await client.recover("buyer@example.com");
```

`getStatus()` does not contact the server. On a first launch with empty storage it records the local install time and reports a trial, including when `startTrial()` cannot reach the server. `refreshInBackground()` renews the license JWT or, if there is no key yet, registers the trial. `activate` requires the network. `recover` always resolves the same way when the server returns 200, whether or not that email has a license.

Public routes (JSON, rate limited per IP; activate and recover are stricter, and activate is also limited per key):

| Method and path | Body | Result |
| --- | --- | --- |
| `POST /v1/{app}/trial` | `machine_hash`, optional `local_started_at`, `platform`, `app_version` | Trial window and trial JWT |
| `POST /v1/{app}/activate` | `key`, `machine_hash`, `machine_name`, `platform`, `app_version` | License JWT, or `invalid_key`, `revoked`, `machine_limit_reached`, `app_disabled` |
| `POST /v1/{app}/validate` | `key`, `machine_hash` | Refreshed JWT, or `revoked`, `not_activated` |
| `POST /v1/{app}/deactivate` | `key`, `machine_hash` | Frees that slot |
| `POST /v1/{app}/recover` | `email` | Always the same 200 body |
| `POST /v1/{app}/reset-machines/request` | `key` | Emails a code, or `reset_limit_reached` |
| `POST /v1/{app}/reset-machines/confirm` | `key`, `code`, `machine_hash`, optional device fields | Clears slots, activates this machine, returns a JWT |

## Development

Requires Node.js 22+.

```bash
npm install
npm test
npm run typecheck
npm run lint
npm run build -w @linkfuture/license-client
```

Server tests run on the Workers Vitest pool (Miniflare + D1) and cover webhook idempotency, $0 checkouts, missing metadata, refund and dispute revocation, machine limits, inactive machines, cross-app keys, offline JWT checks, trials, reset quotas, recovery, and stats. Client tests cover offline verification and the local trial clock.

## Security

- Do not commit secrets. `server/.dev.vars` is gitignored. Production secrets are `ADMIN_TOKEN`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `RESEND_API_KEY`, `LICENSE_ENCRYPTION_KEY`, and one `APP_KEY_<SLUG>` per app.
- Admin authentication compares SHA-256 digests of the presented token and `ADMIN_TOKEN` in constant time. An empty token is rejected.
- Webhook signatures are required. The raw body is what is signed.
- Public routes are rate limited in D1 per IP. Activate is additionally limited per IP and per submitted key. Recover is limited per IP and per email. Reset is limited per IP, and successful resets are limited per license.
- License lookup uses the SHA-256 of the canonical key. The plaintext key exists only in process memory, in the buyer email, and inside `key_enc`.
- Reset codes are stored as SHA-256(pepper + license id + code). The pepper is `LICENSE_ENCRYPTION_KEY`.
- JWTs are not encrypted; they are signed. Do not put buyer emails or raw machine ids in them. Anyone who copies a JWT to another machine fails the `mid` check. Anyone who edits a byte fails the signature check.
- Offline grace is intentional. Revocation stops renewal immediately and locks the app when `exp` passes, including if the app was offline at the moment of the refund.
- The inactive-device rule only affects whether a new activation is allowed. It does not delete history.
- Rate-limit counters and encrypted keys are operational data. Treat a D1 backup as sensitive even though raw keys are not stored.

## Implementation notes

- Key format is `PREFIX-XXXXX-XXXXX-XXXXX-XXXXX` (20 Crockford characters, 100 bits).
- `kind` is an extra JWT claim so a trial token cannot be mistaken for a license. Required claims from the product spec are unchanged.
- Self-service reset confirms the code, removes every activation, and activates the requesting machine in the same call.
- There is no endpoint that mints a license key. Admin routes can register apps, update app settings, revoke a license (`revoke_reason = admin`), and unbind one activation. Those are operator actions, not a second issuance channel.
