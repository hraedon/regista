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
| `vault:` | `vault:secret/data/regista/key` | HashiCorp Vault KV v2 (requires `pip install regista[vault]`) |
| `azure:` | `azure:key-name` | Azure Key Vault (requires `pip install regista[azure]`) |
| `windows:` | `windows:AQAAANCMnd8BFdERjHoAwE/...` | Windows DPAPI-protected blob (base64). Auto-available on win32; uses `CRYPTPROTECT_LOCAL_MACHINE` scope. Encrypt with `regista.secrets.protect_windows_secret(data)`. |

If no prefix is recognized, the resolver treats the value as a file path.

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

## 5. Version Surface

`regista version --json` reports the four interop versions a consumer must
pin against:

```json
{
  "component": "regista",
  "library_version": "0.5.1",
  "schema_version": 38,
  "canonical_workflow_version": "1",
  "envelope_version": 4,
  "canonical_workflow_hash": "sha256hex...",
  "available_signing_schemes": ["ed25519", "hmac-sha256"]
}
```

| Field | What it pins |
|-------|-------------|
| `library_version` | The regista Python package version |
| `schema_version` | The highest migration number (DB schema) |
| `canonical_workflow_version` | The `version` field in `canonical.workflow.yaml` |
| `envelope_version` | The signed-envelope format version (currently v4) |
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
