# sing-box-copilot

Small CLI tool for generating sing-box users, client subscriptions, and server-side inbounds.

## Commands

Bootstrap the first user in an empty database:

```sh
DATABASE_URL=postgres://... \
sing-box-copilot bootstrap \
  --name chao \
  --email zhangchao050530@gmail.com \
  --password 'change-me'
```

`bootstrap` writes directly to PostgreSQL, only works when `users` is empty, and returns the first user's token plus an 8-character invite code as JSON.

Create an insert statement:

```sh
sing-box-copilot create \
  --name chao \
  --email zhangchao050530@gmail.com \
  --password 'change-me'
```

The command prints the plaintext token once and an `INSERT INTO users ... RETURNING uuid;` statement.
Generated tokens always use the fixed `verzea_` prefix.

Use JSON output when another backend wants to call it:

```sh
sing-box-copilot create \
  --name chao \
  --email zhangchao050530@gmail.com \
  --password 'change-me' \
  --json
```

Generate a sing-box subscription for one enabled user:

```sh
DATABASE_URL=postgres://... \
SING_BOX_CONFIG_PATH=~/.config/sing-box/config.json \
sing-box-copilot generate-subscription a03faa38-dea9-4c15-9d56-71c4757b572c
```

This writes `a03faa38-dea9-4c15-9d56-71c4757b572c.json` in the current directory. Use `--output-dir <dir>` to choose another directory.

Generate subscription files:

```sh
sing-box-copilot generate-subscription <uuid> --format clash
sing-box-copilot generate-subscription <uuid> --format shadowrocket
```

Subscription output is template-based. The CLI reads the matching file from
`templates` and merges the generated server fragment into it:

- `sing-box` -> `sing-box/config.json`
- `clash` / `mihomo` -> `clash/config.yaml`
- `shadowrocket` -> `shadowrocket/config.conf`

Use `SUBSCRIPTION_TEMPLATE_DIR` to point at a custom template directory.

For text formats such as Clash and Shadowrocket, merging means appending a full generated section at the end of the template. For sing-box, merging parses the template JSON and appends generated outbound objects to the top-level `outbounds` array, equivalent to a jq-style `.outbounds += $fragment` operation.

Generated subscriptions use the sing-box server config pointed to by `SING_BOX_CONFIG_PATH` as the source of truth: the public hostname is inferred from inbound `handshake.server` or `tls.server_name`, protocol ports are read from each supported inbound's `listen_port`, and node order follows the supported proxy inbound order in that file. Templates are only client-specific outer config.

Generate subscriptions for all enabled users:

```sh
DATABASE_URL=postgres://... \
sing-box-copilot generate-subscription-all --output-dir /etc/sing-box/subscribe
```

Generate server-side sing-box config from the database:

```sh
DATABASE_URL=postgres://... \
SING_BOX_CONFIG_PATH=~/.config/sing-box/config.json \
sing-box-copilot generate-config
```

`generate-config` reads one complete sing-box config file, updates the top-level `inbounds` array with enabled database users, and writes the same file back atomically. `SING_BOX_CONFIG_PATH` defaults to `~/.config/sing-box/config.json`.

Rotate a user's subscription token:

```sh
sing-box-copilot rotate <uuid>
```

Enable or disable a user:

```sh
sing-box-copilot enable <uuid>
sing-box-copilot disable <uuid>
```

Inspect derived protocol credentials:

```sh
DATABASE_URL=postgres://... \
sing-box-copilot inspect <uuid>
```

Run the GraphQL backend:

```sh
DATABASE_URL=postgres://... \
cargo run --bin sing-box-server
```

The server listens on `HOST:PORT`, defaulting to `0.0.0.0:2002`, and exposes GraphQL at `/graphql`.

Register a user:

```graphql
mutation {
  register(input: {
    name: "chao"
    email: "chao@example.com"
    password: "change-me"
    inviteCode: "aB3dE5gH"
  }) {
    uuid
    token
    tokenPrefix
  }
}
```

Reset your invite code:

```graphql
mutation {
  resetInviteCode(token: "verzea_xxx") {
    uuid
    inviteCode
    inviteCodePrefix
  }
}
```

Login:

```graphql
mutation {
  login(input: {
    email: "chao@example.com"
    password: "change-me"
  }) {
    uuid
    name
    email
    token
    tokenPrefix
  }
}
```

Generate a subscription by token:

```graphql
query {
  subscription(token: "verzea_xxx", format: "sing-box") {
    uuid
    format
    extension
    content
  }
}
```

Direct subscription links are also available for clients that cannot call GraphQL:

```text
GET /subscription/sing-box?token=verzea_xxx
GET /subscription/clash?token=verzea_xxx
GET /subscription/shadowrocket?token=verzea_xxx
```

## Environment

- `DATABASE_URL`: PostgreSQL connection string. Required by `generate-config`, `generate-subscription`, `generate-subscription-all`, and `inspect`.
- `SING_BOX_CONFIG_PATH`: complete sing-box server config path used by `generate-config` and `generate-subscription`. Default: `~/.config/sing-box/config.json`.
- `NODE_LOCATION`: country or region code for generated node names, such as `JP`, `US`, or `SG`. Default: `Unknown`.
- `NODE_NAME_BASE`: full node name prefix override, such as `🇯🇵 Japan`. When set, it overrides `NODE_LOCATION`.
- `MASTER_SECRET`: optional server-side secret for deriving protocol passwords. When empty, passwords are derived from the user token only.
- `EMAIL_ALLOW_LIST`: optional comma- or newline-separated email allow list for GraphQL registration. Empty means all emails are allowed.
- `SUBSCRIPTION_TEMPLATE_DIR`: directory containing client subscription templates. Default: `templates`.

The CLI reads `MASTER_SECRET` from the environment and passes it to the library explicitly. Library callers should pass the master secret through the public API instead of relying on environment lookup.

VMess WebSocket path is derived per user and matches the derived VMess password value.

Node names are generated from the supported proxy inbounds in `SING_BOX_CONFIG_PATH`, using `{region flag emoji} {region name} {two-digit number}`, such as `🇯🇵 Japan 01`, `🇯🇵 Japan 02`, and `🇯🇵 Japan 03`. Client formats emit the subset of those generated nodes that the target client format can represent.

Proxy protocol ports are not configured through environment variables. They come from the matching sing-box inbound `listen_port` values.

## Expected Tables

This first version stores `token` in plaintext so the CLI can derive protocol passwords without receiving a request token.

See `sql/schema.sql`.

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  invited_by_uuid UUID REFERENCES users(uuid),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  token_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS invited_by_uuid UUID REFERENCES users(uuid);

CREATE TABLE user_invites (
  user_uuid UUID PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  code_prefix TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`password_hash` must be an Argon2 PHC string. `token` is stored in plaintext in this first version.

Protocol passwords are derived instead of stored. Set `MASTER_SECRET` from an external secret manager to make the derivation depend on a server-side secret. Leave it empty for the simpler token-only derivation.
