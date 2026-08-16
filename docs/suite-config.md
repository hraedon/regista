# Suite Configuration Contract

> **Plan 025 WI-1.1 / WI-3.1 / WI-4.1** — the canonical config vocabulary,
> doctor shape, and version surface that every suite member conforms to.

## 1. Canonical Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `REGISTA_DSN` | Postgres connection string for the regista store | Yes |
| `REGISTA_KEY_PATH` | Path to signing key-set JSON (or secret-backend ref) | Yes |
| `REGISTA_REQUIRE_SSL` | Reject connections without SSL (`true`/`false`) | No (default `false`) |
| `REGISTA_PROJECT` | Project (schema) slug — shared default; each tool may set its own `<TOOL>_PROJECT` | Yes |

### Deprecated Aliases (one-release)

| Old name | Canonical name |
|----------|---------------|
| `REGISTA_HMAC_KEY_PATH` | `REGISTA_KEY_PATH` |

Aliases work in all resolution layers (env vars, suite.env files). They will
be removed in the release after this one ships.

## 2. Layered Resolution

`regista.config.resolve()` resolves each variable from four layers,
highest-precedence first:

1. **Process environment** — `os.environ` (explicit overrides)
2. **Per-user file** — `~/.config/agent-suite/suite.env` (override path with `$AGENT_SUITE_CONFIG`)
3. **System file** — `/etc/agent-suite/suite.env` (Linux) or `%ProgramData%\agent-suite\suite.env` (Windows)
4. **Default** — unset (caller decides what's required)

The first layer that provides a value wins. If the canonical name is absent,
the resolver checks deprecated aliases at the same layer before moving to the
next layer.

### Resolution result

`resolve()` returns a `SuiteConfig` with `dsn`, `key_path`, `require_ssl`,
`project`, and `source` (a dict mapping each resolved variable to the layer
that provided it, e.g. `"REGISTA_DSN": "env"`, `"REGISTA_KEY_PATH": "user:/home/.../suite.env"`).

## 3. Secret Backend Resolution

`regista.secrets.resolve(ref)` resolves a secret reference to raw bytes.
`REGISTA_KEY_PATH` and any DSN password may use this indirection.

### Reference syntax

| Prefix | Example | Behavior |
|--------|---------|----------|
| `file:` (default) | `file:/path/to/key.json` or `/path/to/key.json` | Read file contents as bytes |
| `env:` | `env:MY_SECRET_VAR` | Read environment variable as UTF-8 bytes |
| `literal:` | `literal:plain-text-value` | Return the literal string as bytes |
| `vault:` | `vault:kv/agent-suite/hosts/HOSTNAME/regista/hmac_key` | HashiCorp Vault KV v2 (requires `pip install regista[vault]`) |
| `azure:` | `azure:key-name` | Azure Key Vault (requires `pip install regista[azure]`) |
| `windows:` | `windows:AQAAANCMnd8BFdERjHoAwE/...` | Windows DPAPI-protected blob (base64). Auto-available on win32; uses `CRYPTPROTECT_LOCAL_MACHINE` scope. Encrypt with `regista.secrets.protect_windows_secret(data)`. |

If no prefix is recognized, the resolver treats the value as a file path.

### Vault ref shape — three traps

The `vault:` ref is `<mount>/<path…>/<field>`, and **the field is the last path
segment**. Three shapes that look right and are not:

1. **`#field` does not exist.** `vault:kv/a/b/regista#hmac_key` does not fail —
   it parses to mount `kv`, path `a/b`, and a field literally named
   `regista#hmac_key`, i.e. a *different, neighbouring* secret. A permissive
   policy will happily read it. Use `vault:kv/a/b/regista/hmac_key`.
2. **There is no default mount.** A ref needs at least four segments; the mount
   is whatever your Vault actually has (`kv`, not necessarily `secret`).
3. **`vault:` refs resolve only where `hvac` is importable.** A provider is
   registered per *process*, so `vault` appearing in `regista secrets
   --list-providers` says nothing about whether another component can resolve its
   own refs. Install the extra for each component and check each one.

Also note `REGISTA_KEY_PATH` is a path to a `keys.json` **file**, not a
resolvable ref. Backend refs belong *inside* that file as per-key `secret_ref` +
`encoding` entries.

### Vault authentication — AppRole and token

The resolver authenticates in exactly one of two ways, and always reports which.

| Method | Declared by | Use |
|--------|-------------|-----|
| **AppRole** | `VAULT_ROLE_ID` (or `VAULT_ROLE_ID_FILE`) **and** `VAULT_SECRET_ID_FILE` (or `VAULT_SECRET_ID`) | Production. Needs **no `VAULT_TOKEN`** anywhere in the environment. |
| **token** | `VAULT_TOKEN` | Dev only (`vault server -dev`). |

| Variable | Meaning |
|----------|---------|
| `VAULT_ADDR` | Vault endpoint. Required for either method. |
| `VAULT_ROLE_ID` | AppRole RoleID, inline. |
| `VAULT_ROLE_ID_FILE` | File holding the RoleID. Takes precedence over the inline form. |
| `VAULT_SECRET_ID_FILE` | File holding the SecretID. **Preferred** — it is where response-wrapped delivery lands, and it keeps the SecretID out of `/proc/<pid>/environ`. |
| `VAULT_SECRET_ID` | SecretID inline. Discouraged; readable from the process environment. |
| `VAULT_SECRET_ID_RESPONSE_WRAPPED` | `1` when `VAULT_SECRET_ID_FILE` holds a **response-wrapping token** rather than the SecretID itself. The host unwraps it for itself on first login. |
| `VAULT_APPROLE_MOUNT_POINT` | AppRole auth mount. Default `approle`. |
| `VAULT_ENV_FILE` | An env-style **plane file** to read `VAULT_*` from (see interop below). Process environment wins over it. |
| `VAULT_TOKEN` | Static token, dev only. |

**Any** AppRole variable being set means AppRole is what you asked for. From that
point `VAULT_TOKEN` is not consulted, and material that is present but unusable
is a hard error naming what to fix. Falling back to the dev method would turn a
broken production posture into a working dev one without saying so — which is
precisely the confusion this refuses to allow.

#### Declaring it on a host

In `/etc/agent-suite/suite.env` (delivered to units via `EnvironmentFile=`, so
systemd-launched services get it too — a wrapper script that injects a token
does not reach them):

```env
VAULT_ADDR=https://vault.example:8200
VAULT_ROLE_ID_FILE=/etc/agent-suite/vault-role-id
VAULT_SECRET_ID_FILE=/etc/agent-suite/vault-secret-id
VAULT_SECRET_ID_RESPONSE_WRAPPED=1
# and deliberately no VAULT_TOKEN
```

Both files should be `0400`/`0600` and owned by the service user.

#### One credential file across components — the acb plane file

acb *provisions* AppRoles and writes a mode-0600, env-style **plane file**
carrying `VAULT_ADDR`, `VAULT_ROLE_ID` and `VAULT_SECRET_ID`, minting a separate
SecretID per harness so each is independently revocable. Those are the same
variable names this resolver reads, so there is **one format**, not two:

```bash
# point regista at the file acb provisioned
VAULT_ENV_FILE=/home/svc/.config/acb/vault.env
```

Only `VAULT*` keys are read from it, so the file may equally be a shared
`suite.env`. `export KEY=value`, quotes and `#` comments are accepted. The
process environment overrides the file — matching acb's own merge — so an
explicit variable still wins, and `regista secrets --auth-status` reports
`plane:VAULT_ROLE_ID` rather than `env:` for values that came from the file, so
provenance points at the right place.

Equivalently, systemd can source the same file with `EnvironmentFile=`; both
routes end at the same variables.

Two points where regista and acb deliberately differ, both intentional:

- **regista fails closed on partial AppRole material; acb falls through to
  `VAULT_TOKEN`.** acb checks `if role_id and secret_id`, so a host with only a
  RoleID quietly authenticates as whatever token is around. regista treats any
  AppRole variable as a declaration of intent and refuses. The strict reading is
  the one to converge on — a silent downgrade to the dev method is the failure
  this whole feature exists to prevent.
- **`VAULT_SECRET_ID_FILE` is not replaced by the plane file.** A plane file holds
  a plain SecretID; response-wrapped delivery lands a *single-use wrapping token*
  that the host must unwrap itself. The two coexist: a plane file can supply
  `VAULT_ADDR`/`VAULT_ROLE_ID` while `VAULT_SECRET_ID_FILE` +
  `VAULT_SECRET_ID_RESPONSE_WRAPPED=1` supplies the SecretID.

#### No ambient credentials

`hvac.Client(url=...)` defaults to `token=None`, which makes hvac call
`get_token_from_env()` — picking up `$VAULT_TOKEN` **and** `~/.vault-token`. The
client is therefore constructed with `token=""`, so it is born holding nothing
and only the explicit auth path gives it a credential. A stray `~/.vault-token`
cannot make an unconfigured host appear to work.

acb applies the same guard on its privileged admin plane
(`onboard.py`); its runtime credential path (`cred_vault.py`) still constructs
`hvac.Client(url=addr, token=env.get("VAULT_TOKEN"))`, which is `None` when the
variable is unset. That is benign when AppRole material is complete (the login
overwrites the token) but not when it is partial: `cred_vault._authenticate`
falls through to `if client.token` and would accept an ambient credential nobody
configured. Reported upstream rather than worked around here.

#### Policy capabilities

For **reading** refs, the role's policy needs `read` on both the data and
metadata paths:

```hcl
path "kv/data/agent-suite/hosts/HOSTNAME/*"     { capabilities = ["read"] }
path "kv/metadata/agent-suite/hosts/HOSTNAME/*" { capabilities = ["read"] }
```

For **custody writes** (`REGISTA_SECRET_BACKEND=vault`, i.e. `enroll_principal` /
`provision-principal` storing a generated key) grant `["create", "update"]`, not
`create` alone: Vault denies a `create`-only credential with `Forbidden` before it
evaluates the check-and-set condition, so a least-privilege policy that omits
`update` fails with a permission error rather than a legible conflict.

#### Response-wrapped SecretID delivery

Only a short-lived, single-use wrapping token crosses onto the host:

```bash
# on the provisioning host, with a token allowed to issue SecretIDs
vault write -f -wrap-ttl=300s auth/approle/role/<role>/secret-id
# ship the printed wrap_info.token to the target as VAULT_SECRET_ID_FILE
```

The unwrapped SecretID is held in memory for the process lifetime, because the
wrapping token is one-shot and a later re-login would otherwise have nothing to
authenticate with.

#### Token lifecycle

An AppRole login yields a **lease**. A long-running process (dossier,
`agent-waked`) re-authenticates before that lease expires, and again if a 403
turns out to be a dead token rather than a policy denial — the two are told apart
by checking whether the token still validates, so a genuine denial is reported at
once instead of driving a login loop. A static `VAULT_TOKEN` cannot be renewed
from nothing: its expiry is reported rather than papered over.

When the SecretID itself expires or runs out of uses, re-login fails closed with
an error naming the re-delivery command.

#### Reporting which method is in use

```bash
regista secrets --auth-status            # human
regista --json secrets --auth-status     # machine-readable
regista secrets --auth-status --probe    # actually authenticate; exit 1 if it fails
```

The report names *where* each credential came from and the current lease — never
a credential value, so it is safe to print, log, and paste into a ticket.
`regista doctor` carries the same fact as `custody:vault_auth`: `ok` for AppRole,
`warn` for a static token (the dev posture), `fail` for AppRole material that is
configured but unusable.

### Windows DPAPI provider

The `windows:` provider decrypts a base64-encoded DPAPI blob using the
machine key (`CRYPTPROTECT_LOCAL_MACHINE`). This works in any Windows session
type — interactive, service, or SSH — because the machine key is always
available. The encryption side (`protect_windows_secret`) tries the fast
ctypes path first and falls back to .NET/PowerShell if the user profile
isn't loaded (e.g. non-interactive SSH sessions).

To create a DPAPI-protected secret:

```python
from regista.secrets import protect_windows_secret

blob = protect_windows_secret(b"my-dsn-password")
# blob is a base64 string — store it in an env var or config file
# Then reference it as: windows:<blob>
```

Or via PowerShell:

```powershell
Add-Type -AssemblyName System.Security
$bytes = [System.Text.Encoding]::UTF8.GetBytes("my-dsn-password")
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
[Convert]::ToBase64String($encrypted)
```

### Available providers

Run `regista secrets --list-providers` to see which backends are installed.
Library consumers should import the stable `regista.secrets` module. Its
`API_VERSION` is `1`; provider-neutral consumers should check that contract in
addition to pinning Regista `>=0.5.1,<0.6`. Its
`known_providers()` and `available_providers()` calls distinguish canonical
reference names from providers actually installed on this host;
`reference_provider(ref, require_explicit=True)` validates a reference without
reading its value. Azure and Windows availability is not a claim of live
backend conformance: Azure requires its optional SDK and Windows DPAPI is
registered only on win32.

### Secret write (custody) — Plan 029

`regista.secrets.store(ref, data)` is the write companion to `resolve`. It is
used by `provision-principal` / `enroll_principal` to custody a freshly
generated Ed25519 private key. Each provider's write behavior:

| Backend | `store()` | Notes |
|---------|-----------|-------|
| `file` | writes `0o600`, atomic (temp + rename); returns `file:<path>` | Default. `private_key_dir` selects the directory. |
| `windows` | DPAPI-protects; returns `windows:<blob>` (the blob IS the ref) | No plaintext on disk. Win32 only. |
| `vault` | KV v2 `create_or_update`; base64-encodes the raw key; returns `vault:<ref>` | Requires `hvac` + a token with write scope. Key-file entry records `encoding: base64`. |
| `azure` | `set_secret`; base64-encodes; returns `azure:<name>` | Requires the Azure SDK + a credential with write scope. `encoding: base64`. |
| `env` / `literal` | raises `SECRET_WRITE_UNSUPPORTED` | Read-only by nature — cannot custody a generated secret. |
| `operator` | raises `SECRET_WRITE_EXTERNAL` | Operator-writes seam (see below). |

#### WI-1.2 decision: write-vs-operator-writes

The configured backend is the source of truth for where a new private key
lands. Custody never silently falls back to `file:`.

- **Self-custody** (`file`/`windows`/`vault`/`azure`): `enroll_principal`
  generates the keypair, writes the private key via `store()`, and records the
  returned ref. The private key is never written to local disk unless the
  backend is `file`. It is never returned to the caller.
- **Operator-custody** (`REGISTA_SECRET_BACKEND=operator`): regista is
  intentionally read-only against the backend. `enroll_principal` does **not**
  generate a keypair — it raises `SECRET_WRITE_EXTERNAL` carrying the ref the
  operator must populate and guidance to use `regista principal register` with
  an operator-generated public key. The operator generates and populates the
  secret out-of-band; regista never holds the private key.

  Rationale: if regista generated the keypair but could not write it to the
  backend, the private key would have nowhere to go (it cannot be returned to
  the caller, and writing it to disk would defeat the purpose). So
  operator-custody means the operator generates the keypair out-of-band and
  registers only the public key. This is a deliberate, documented exception to
  the "humans never handle raw key material" guarantee — it applies only when
  the deployment's backend is not write-accessible by regista.

Select the backend via `REGISTA_SECRET_BACKEND` (or `--secret-backend` on the
CLI). `private_key_dir` is meaningful only for the `file` backend.

## 4. Doctor JSON Contract

`regista doctor --json` emits the canonical health shape:

```json
{
  "component": "regista",
  "version": "0.5.1",
  "reachable": true,
  "schema_version": 38,
  "projects": [{"name": "my_project"}],
  "checks": [
    {"name": "db:reachable", "status": "ok", "detail": "connected"},
    {"name": "schema:my_project", "status": "ok", "detail": "Schema version 38"},
    {"name": "version:schema", "status": "ok", "detail": "Library declares schema 38, envelope 4"},
    {"name": "version:signing_schemes", "status": "ok", "detail": "Available: ed25519, hmac-sha256"}
  ]
}
```

### Check statuses

| Status | Meaning |
|--------|---------|
| `ok` | Check passed |
| `warn` | Potential issue (e.g. migrations pending) |
| `fail` | Check failed (e.g. DB unreachable, schema drift) |
| `skip` | Check not applicable (e.g. no DSN provided) |

A `reachable: false` on an unreachable DSN is a clean status, not a traceback.
Exit code is 1 if any check has status `fail`.

### Project iteration is bounded (WI-244)

Without `--project`, `regista doctor` iterates the `public.projects` catalog
serially — one connection + schema-version probe per project. A diagnostic
path must not do unbounded work (Plan 020 lesson #1): when the catalog holds
more than `--max-projects` (default 25) entries, only the first 25 are checked
individually and a `projects` warn check names the bound:

```json
{"name": "projects", "status": "warn",
 "detail": "19976 projects registered; checked the first 25 — pass --project to target one"}
```

Raise the cap with `--max-projects N` when a deployment genuinely holds many
projects, or pass `--project` to target one. A catalog that large usually
signals leaked project registrations rather than a real deployment.

## 5. Version Surface

`regista version --json` reports the four interop versions a consumer must
pin against:

```json
{
  "component": "regista",
  "library_version": "0.5.1",
  "schema_version": 38,
  "canonical_workflow_version": "3",
  "envelope_version": 5,
  "canonical_workflow_hash": "sha256hex...",
  "available_signing_schemes": ["ed25519", "hmac-sha256"]
}
```

| Field | What it pins |
|-------|-------------|
| `library_version` | The regista Python package version |
| `schema_version` | The highest migration number (DB schema) |
| `canonical_workflow_version` | The `version` field in `canonical.workflow.yaml` |
| `envelope_version` | The latest signed-envelope format emitted by the standard append path (currently v5). Staged parser support does not advance this value until the required writable migration lands. |
| `canonical_workflow_hash` | SHA-256 of the canonical workflow YAML bytes |
| `available_signing_schemes` | Signing schemes registered in the runtime |

A `SUITE.lock` file records these versions. The suite-interop CI asserts them.

## 6. Principal Key Registry (Plan 026)

`regista principal` subcommands manage the per-project principal→public-key
registry, enabling per-actor cryptographic non-repudiation.

```bash
# List principal keys
regista principal list --principal alice@example.com

# Register a public key (base64)
regista principal register \
  --principal alice@example.com \
  --public-key <base64-pubkey> \
  --scheme ed25519

# Revoke a key
regista principal revoke \
  --principal alice@example.com \
  --key-id pk_1234_abc \
  --reason "compromised"
```

### Registry model

- Each `principal_id` can have multiple key entries (for rotation)
- Only one key is `active` at a time; previous keys are `superseded`
- A `revoked` key stops verifying new events but past events it signed stay valid
- `valid_from`/`valid_to` windows support time-bounded key validity
- Registration/rotation/revocation are themselves auditable operations
