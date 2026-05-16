# xero-rest-mcp

A sidecar MCP server that exposes the Xero REST endpoints the upstream
[XeroAPI/xero-command-line](https://github.com/XeroAPI/xero-command-line)
doesn't implement. Pairs with
[xero-mcp-wrapper](https://github.com/justinritchie/xero-mcp-wrapper):
use the CLI wrapper for everything it covers, this sidecar for the gaps.

## What this exposes

| Tool                          | Use case                                                   |
| ----------------------------- | ---------------------------------------------------------- |
| `bank_transfers_create`       | Inter-account transfers, posted as native Xero Transfers (auto-creates both sides) |
| `batch_payments_create`       | One bank-line paying N invoices, shows as ONE entry in Xero UI |
| `attachments_upload`          | Attach PDFs / images / files to bills, bank-tx, invoices, etc. |
| `attachments_list`            | List attachments on any Xero record |
| `bank_transactions_update`    | Edit a posted bank-tx (fix reference, swap GL account, etc.) |
| `bank_transactions_void`      | Void / delete a posted bank-tx |
| `invoices_void`               | Void / delete a posted invoice or bill |
| `whoami`                      | Health check — confirm auth is alive, see token expiry |

## Auth — piggybacks on the xero CLI's existing OAuth tokens

This sidecar does NOT implement its own OAuth flow. It reads the xero
CLI's encrypted token store on disk:

```
~/.config/xero-command-line/config.json    # profiles + clientIds (plaintext)
~/.config/xero-command-line/tokens.json    # per-profile tokens (ENCRYPTED)
```

**`tokens.json` is AES-256-GCM encrypted at rest.** Each value is
`base64(IV[12] + AuthTag[16] + Ciphertext)`. The CLI stores the 32-byte
encryption key in the **macOS Keychain** at:

- Service: `xero-command-line`
- Account: `encryption-key`

The sidecar reads the key from Keychain via `security
find-generic-password`. The first time the sidecar (a different binary
from the CLI) tries to read, macOS will prompt the user with **"Allow /
Always Allow / Deny"**. Click **Always Allow** so subsequent calls work
silently.

When the access token is within 2 minutes of expiry, the sidecar refreshes
via `POST https://identity.xero.com/connect/token`, then re-encrypts the
new tokens with the same Keychain key and writes them back to
`tokens.json`. The CLI picks up the refreshed tokens on its next
invocation. Refresh writes are guarded by `fcntl.LOCK_EX` + atomic
rename so the CLI and sidecar can't double-refresh and invalidate each
other's tokens (Xero rotates refresh tokens on every refresh).

**Zero new auth flow. Zero new app registration with Xero. Tokens stay
where they already live, in the same encrypted file, with the same
Keychain key.**

If you've never run `xero auth login -p <profile>` for a profile, do
that first — this sidecar can't bootstrap fresh credentials, only refresh
existing ones.

## Multi-org support

Each Xero org is a separate **profile** in the CLI. To use this sidecar
with N orgs:

1. Authorize each org once via the CLI: `xero auth login -p <profile-name>`
2. Add a separate Claude Desktop entry per org, scoped via `XERO_PROFILE`:

```json
{
  "mcpServers": {
    "xero-xenetwork-rest": {
      "command": "/Users/justinritchie/justinritchie-mcp-servers/xero-rest-mcp/.venv/bin/xero-rest-mcp",
      "env": {
        "XERO_PROFILE": "xe",
        "XERO_ACCOUNT_LABEL": "XE Network"
      }
    },
    "xero-otherorg-rest": {
      "command": "/Users/justinritchie/justinritchie-mcp-servers/xero-rest-mcp/.venv/bin/xero-rest-mcp",
      "env": {
        "XERO_PROFILE": "otherorg",
        "XERO_ACCOUNT_LABEL": "Other Org Name"
      }
    }
  }
}
```

`XERO_ACCOUNT_LABEL` prepends `[Xero org: <label>]` to every tool's
description so MCP semantic search disambiguates between the instances
(same pattern as `craft-mcp`'s `CRAFT_ACCOUNT_LABEL`).

The Keychain key is **shared across all profiles** — one Always Allow
click authorizes the sidecar for every org.

## Install

```bash
cd ~/justinritchie-mcp-servers/xero-rest-mcp
uv sync                                 # creates .venv with deps
.venv/bin/xero-rest-mcp                 # quick test — hangs on stdio, ^C
```

## Concurrency safety

The sidecar and the xero CLI both touch `tokens.json`. Refresh is guarded
by `fcntl.LOCK_EX` on tokens.json plus atomic rename, so a parallel CLI
invocation can't double-refresh and invalidate one set of tokens.

## Security notes

- The Keychain key grants access to the access + refresh tokens for ALL
  configured Xero profiles. Anyone who can read the Keychain item can
  act as your Xero user against every authorized org.
- The sidecar caches the Keychain key in process memory (via `lru_cache`)
  for the lifetime of the MCP server process. macOS only prompts on the
  first read per binary identity.
- Tokens are never persisted as plaintext — the sidecar decrypts only
  in-memory for outbound requests, and re-encrypts before writing
  refreshed tokens back to disk.
- The CLI's `accounting.*` scopes include write access. This sidecar can
  create, update, void, and attach files to records in your Xero org.
  Use it as carefully as the CLI itself.
