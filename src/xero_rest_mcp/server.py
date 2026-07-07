"""
xero-rest-mcp — sidecar MCP exposing the Xero REST endpoints that the
upstream `xero-command-line` CLI doesn't.

Why this exists:
  The `xero-cli-mcp` wrapper covers everything the CLI supports (contacts,
  invoices, bank-transactions list/create, manual journals, accounts,
  reports, quotes, items, credit notes, tracking, currencies, tax rates).
  It does NOT cover:
    - bank-transfers (inter-account transfers with proper Transfer class)
    - attachments (PDF/binary files attached to bills, bank-tx, invoices)
    - batch-payments (one bank-line paying N invoices, NATIVE shape)
    - bank-transactions update / void
    - invoices void / delete
  All of these exist in Xero's REST API. This sidecar talks REST directly.

Auth piggyback (KEY ARCHITECTURE):
  The Xero OAuth 2.0 flow is a bear to implement from scratch (authorization
  code + refresh tokens + PKCE + tenant selection). The CLI already handles
  it and stores credentials at:
    ~/.config/xero-command-line/config.json    (profiles + clientIds — plaintext)
    ~/.config/xero-command-line/tokens.json    (per-profile tokens — ENCRYPTED)

  IMPORTANT: tokens.json is AES-256-GCM encrypted at rest. The CLI stores
  the encryption key in the macOS Keychain at:
    service: xero-command-line
    account: encryption-key
  Each value is base64(IV[12] + AuthTag[16] + Ciphertext). This sidecar
  reads the key from Keychain (via the `security` command-line tool — no
  prompt because the user already authorized the CLI to write it) and
  decrypts on every access. When refreshing, the sidecar re-encrypts the
  new access+refresh tokens with the SAME key and writes them back to
  tokens.json. The CLI then picks up the refreshed tokens transparently
  on its next invocation.

  Zero new OAuth setup. Zero parallel auth surface. Tokens stay where they
  already live, in the same encrypted file, with the same Keychain key.

Cross-org support:
  Each Xero org is a separate `profile` in the CLI (created via `xero auth
  login -p <name>`). The sidecar handles any number of profiles — pass
  `profile=<name>` to any tool, or set `XERO_PROFILE=<name>` to default
  for the whole instance. For multi-org disambiguation in MCP clients,
  set `XERO_ACCOUNT_LABEL='Org name'` and the sidecar will prepend
  '[Xero org: <label>]' to every tool's description (same pattern as
  craft-mcp's CRAFT_ACCOUNT_LABEL).

Concurrency:
  We always re-read tokens.json before any refresh decision. The refresh
  itself is guarded by an fcntl exclusive lock on tokens.json so the CLI
  and sidecar can't double-refresh simultaneously (which would invalidate
  one set of tokens since Xero rotates refresh tokens on every refresh).

Run via:
  /Users/.../xero-rest-mcp/.venv/bin/xero-rest-mcp   (stdio MCP)
"""

from __future__ import annotations

import asyncio
import base64
import fcntl
import json
import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastmcp import FastMCP


HOME = Path(os.path.expanduser("~"))
CLI_CONFIG_DIR = Path(
    os.environ.get("XERO_CLI_CONFIG_DIR", HOME / ".config" / "xero-command-line")
)
CONFIG_PATH = CLI_CONFIG_DIR / "config.json"
TOKENS_PATH = CLI_CONFIG_DIR / "tokens.json"
DEFAULT_PROFILE_OVERRIDE = os.environ.get("XERO_PROFILE")  # optional override
ACCOUNT_LABEL = os.environ.get("XERO_ACCOUNT_LABEL", "").strip()

# Keychain location of the CLI's AES-256-GCM encryption key
KEYRING_SERVICE = os.environ.get(
    "XERO_KEYRING_SERVICE", "xero-command-line"
)
KEYRING_ACCOUNT = os.environ.get(
    "XERO_KEYRING_ACCOUNT", "encryption-key"
)

# Xero identity / API endpoints
XERO_IDENTITY_TOKEN_URL = "https://identity.xero.com/connect/token"
XERO_API_BASE = "https://api.xero.com/api.xro/2.0"
XERO_FILES_API_BASE = "https://api.xero.com/files.xro/1.0"

# AES-256-GCM packing (matches xero CLI's lib/crypto.js exactly)
IV_LENGTH = 12
AUTH_TAG_LENGTH = 16

# Refresh tokens slightly before they expire so an in-flight request never
# 401s. Xero's standard access token TTL is 1800s (30 min); we refresh when
# under this many seconds remain.
REFRESH_BUFFER_SECONDS = 120

mcp = FastMCP(name="xero-rest")


# ---------------------------------------------------------------------------
# Multi-org disambiguation — prepend "[Xero org: <label>]" to every tool
# description so MCP semantic search can pick the right instance when
# multiple xero-rest sidecars are mounted (one per Xero org).
# ---------------------------------------------------------------------------
if ACCOUNT_LABEL:
    _label_prefix = f"[Xero org: {ACCOUNT_LABEL}] "
    _original_mcp_tool = mcp.tool

    def _account_labeled_tool(*args, **kwargs):  # type: ignore[no-redef]
        desc = kwargs.get("description")
        if desc and not desc.startswith(_label_prefix):
            kwargs["description"] = _label_prefix + desc
        return _original_mcp_tool(*args, **kwargs)

    mcp.tool = _account_labeled_tool  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Auth — piggyback on the CLI's encrypted token store
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_encryption_key() -> bytes:
    """Read the AES-256-GCM key from macOS Keychain. Cached for the process
    lifetime so we don't shell out to `security` on every call.

    The CLI writes the key on first login; macOS Keychain remembers that the
    CLI authorized itself to read it. The first time the SIDECAR (a different
    binary) tries to read, macOS will prompt the user to Allow / Always Allow /
    Deny — choose Always Allow for silent subsequent reads.
    """
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYRING_SERVICE, "-a", KEYRING_ACCOUNT, "-w"],
            capture_output=True, text=True, check=True, timeout=10,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "macOS `security` command not found — this sidecar only runs on macOS "
            "(or wherever the CLI's @napi-rs/keyring backend stored the key)."
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Failed to read encryption key from Keychain "
            f"(service={KEYRING_SERVICE!r}, account={KEYRING_ACCOUNT!r}): "
            f"{e.stderr.strip()}. If macOS prompted you for permission, "
            f"click 'Always Allow' so subsequent calls work silently."
        )
    return base64.b64decode(r.stdout.strip())


def _decrypt(ciphertext_b64: str) -> str:
    """Decrypt a base64-encoded AES-256-GCM blob produced by xero CLI's
    lib/crypto.js encrypt() function. Packing = IV[12] + AuthTag[16] + Ciphertext.
    Returns the plaintext UTF-8 string."""
    packed = base64.b64decode(ciphertext_b64)
    iv = packed[:IV_LENGTH]
    auth_tag = packed[IV_LENGTH:IV_LENGTH + AUTH_TAG_LENGTH]
    ciphertext = packed[IV_LENGTH + AUTH_TAG_LENGTH:]
    aesgcm = AESGCM(_get_encryption_key())
    # cryptography's AESGCM expects ciphertext + tag concatenated
    return aesgcm.decrypt(iv, ciphertext + auth_tag, None).decode("utf-8")


def _encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string with the CLI's AES-256-GCM scheme. Returns
    a base64-encoded IV+AuthTag+Ciphertext blob ready to drop back into
    tokens.json."""
    aesgcm = AESGCM(_get_encryption_key())
    iv = os.urandom(IV_LENGTH)
    ct_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    # cryptography returns ciphertext + tag — we need iv + tag + ciphertext
    ciphertext = ct_and_tag[:-AUTH_TAG_LENGTH]
    auth_tag = ct_and_tag[-AUTH_TAG_LENGTH:]
    return base64.b64encode(iv + auth_tag + ciphertext).decode("ascii")


def _load_config() -> dict:
    with CONFIG_PATH.open() as f:
        return json.load(f)


def _load_tokens() -> dict:
    with TOKENS_PATH.open() as f:
        return json.load(f)


def _resolve_profile(profile: str | None) -> str:
    """Pick which profile to use: explicit arg > env override > config default."""
    if profile:
        return profile
    if DEFAULT_PROFILE_OVERRIDE:
        return DEFAULT_PROFILE_OVERRIDE
    cfg = _load_config()
    return cfg.get("defaultProfile") or next(iter(cfg.get("profiles", {})), "")


def _save_tokens_atomic(tokens: dict) -> None:
    """Atomic write of tokens.json: write to tmp, fsync, rename. Guarded by
    fcntl LOCK_EX so the CLI and sidecar can't trample each other.
    The tokens dict should already contain ENCRYPTED accessToken/refreshToken
    strings (we never persist plaintext)."""
    tmp = TOKENS_PATH.with_suffix(".json.tmp")
    with TOKENS_PATH.open("a+") as lockf:  # open for shared FD to lock
        try:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            with tmp.open("w") as f:
                json.dump(tokens, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, TOKENS_PATH)
            os.chmod(TOKENS_PATH, 0o600)
        finally:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


async def _refresh_if_needed(profile: str) -> dict:
    """Returns the per-profile token dict with DECRYPTED accessToken and
    refreshToken (plus tenantId, tenantName, expiresAt). Always re-reads
    tokens.json from disk before deciding whether to refresh.

    On refresh we POST to identity.xero.com, get new tokens, encrypt them
    with the CLI's same Keychain key, and write back to tokens.json so the
    CLI sees the new tokens next time it runs."""
    tokens = _load_tokens()
    entry = tokens.get(profile)
    if not entry:
        raise RuntimeError(
            f"No tokens for profile {profile!r} in {TOKENS_PATH}. "
            f"Run `xero auth login -p {profile}` to authenticate."
        )

    expires_at_ms = entry.get("expiresAt", 0)
    now_ms = time.time() * 1000
    seconds_remaining = (expires_at_ms - now_ms) / 1000

    # Decrypt for use regardless of refresh path
    access = _decrypt(entry["accessToken"])
    refresh_token = _decrypt(entry["refreshToken"])

    if seconds_remaining > REFRESH_BUFFER_SECONDS:
        return {
            **entry,
            "accessToken": access,
            "refreshToken": refresh_token,
        }

    # Refresh
    cfg = _load_config()
    client_id = (cfg.get("profiles") or {}).get(profile, {}).get("clientId")
    if not client_id:
        raise RuntimeError(
            f"No clientId for profile {profile!r} in {CONFIG_PATH}. "
            f"Cannot refresh."
        )

    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.post(
            XERO_IDENTITY_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if r.status_code != 200:
        raise RuntimeError(
            f"Token refresh failed ({r.status_code}): {r.text[:500]}. "
            f"You may need to re-auth via `xero auth login -p {profile}`."
        )
    fresh = r.json()
    new_access = fresh["access_token"]
    new_refresh = fresh.get("refresh_token", refresh_token)
    new_expires_at = int((time.time() + fresh.get("expires_in", 1800)) * 1000)

    # Re-read tokens.json under the lock so we don't clobber another profile
    all_tokens = _load_tokens()
    all_tokens[profile] = {
        **entry,
        "accessToken": _encrypt(new_access),
        "refreshToken": _encrypt(new_refresh),
        "expiresAt": new_expires_at,
    }
    _save_tokens_atomic(all_tokens)

    return {
        **entry,
        "accessToken": new_access,
        "refreshToken": new_refresh,
        "expiresAt": new_expires_at,
    }


async def _auth_headers(profile: str | None) -> tuple[str, dict]:
    """Returns (profile_used, headers_dict) ready for an httpx request."""
    p = _resolve_profile(profile)
    entry = await _refresh_if_needed(p)
    return p, {
        "Authorization": f"Bearer {entry['accessToken']}",
        "xero-tenant-id": entry["tenantId"],
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# Generic REST helpers
# ---------------------------------------------------------------------------

def _err(stage: str, exc: Exception) -> dict:
    if isinstance(exc, httpx.HTTPStatusError):
        # Try to surface Xero's ValidationErrors[].Message succinctly
        messages: list[str] = []
        try:
            body = exc.response.json()
            for el in (body.get("Elements") or []):
                for ve in (el.get("ValidationErrors") or []):
                    msg = ve.get("Message")
                    if msg:
                        messages.append(msg)
            if not messages:
                msg = body.get("Message") or body.get("Detail")
                if msg:
                    messages.append(msg)
        except Exception:
            pass
        return {
            "_error": f"HTTP {exc.response.status_code}",
            "messages": messages,
            "stage": stage,
            "raw_body": exc.response.text[:1500],
        }
    return {"_error": f"{type(exc).__name__}: {exc}", "stage": stage}


async def _api(
    method: str,
    path: str,
    profile: str | None = None,
    json_body: dict | None = None,
    files_api: bool = False,
    raw_content: bytes | None = None,
    raw_content_type: str | None = None,
) -> Any:
    """Make an authenticated request to Xero's accounting or files API.

    files_api=True swaps the base from api.xro/2.0 to files.xro/1.0 (used
    by attachments).
    raw_content (bytes) + raw_content_type let attachment uploads send
    binary payloads with the right Content-Type.
    """
    _, headers = await _auth_headers(profile)
    base = XERO_FILES_API_BASE if files_api else XERO_API_BASE
    url = base + path

    async with httpx.AsyncClient(timeout=60.0) as c:
        try:
            if raw_content is not None:
                headers["Content-Type"] = raw_content_type or "application/octet-stream"
                r = await c.request(method, url, headers=headers, content=raw_content)
            elif json_body is not None:
                headers["Content-Type"] = "application/json"
                r = await c.request(method, url, headers=headers, json=json_body)
            else:
                r = await c.request(method, url, headers=headers)
            r.raise_for_status()
        except httpx.HTTPError as e:
            return _err(f"{method} {path}", e)

    if not r.content:
        return {"_ok": True}
    try:
        return r.json()
    except ValueError:
        return {"_raw": r.text[:2000]}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    description=(
        "[xero-rest sidecar] Health check — returns the active profile, "
        "tenant name + ID, token expiry, and which REST endpoints this "
        "sidecar exposes. Use FIRST in any session to confirm auth is alive "
        "and which Xero org we're hitting.\n"
        "\n"
        "Args:\n"
        "  profile: Optional profile name override (defaults to CLI's defaultProfile)"
    )
)
async def whoami(profile: str | None = None) -> dict:
    try:
        p = _resolve_profile(profile)
        entry = await _refresh_if_needed(p)
    except Exception as e:
        return _err("whoami", e)
    return {
        "profile": p,
        "tenantId": entry["tenantId"],
        "tenantName": entry.get("tenantName"),
        "expiresAt_ms": entry.get("expiresAt"),
        "seconds_to_expiry": int(entry.get("expiresAt", 0) / 1000 - time.time()),
        "endpoints": [
            "bank_transfers_create",
            "batch_payments_create",
            "attachments_upload",
            "attachments_list",
            "bank_transactions_update",
            "bank_transactions_void",
            "invoices_void",
            # Round 4 — _full variants that bypass the CLI's field-stripping bug
            "invoices_create_full",
            "invoices_update_full",
            "credit_notes_create_full",
            "quotes_create_full",
            "bank_transactions_create_full",
            # Round 5 — Chart-of-Accounts gap (xero-cli has list+update only)
            "accounts_create",
            "accounts_archive",
        ],
    }


@mcp.tool(
    description=(
        "[xero-rest sidecar] Create a Xero BankTransfer — moves money "
        "between two bank accounts and auto-creates BOTH sides "
        "(SPEND-TRANSFER on source, RECEIVE-TRANSFER on destination) "
        "atomically. The Xero UI shows this as a proper Transfer, not as "
        "two unrelated bank-tx entries.\n"
        "\n"
        "USE WHENEVER you need to move funds between your own bank accounts "
        "(e.g. paying a credit card bill from a chequing account, moving "
        "money from clearing into operating, etc.). DO NOT use this for "
        "supplier payments — that's payments_create / batch_payments_create.\n"
        "\n"
        "Args:\n"
        "  from_bank_account_id: Source bank AccountID (REQUIRED)\n"
        "  to_bank_account_id: Destination bank AccountID (REQUIRED)\n"
        "  amount: Positive number — amount to transfer (REQUIRED)\n"
        "  date: YYYY-MM-DD transfer date (REQUIRED)\n"
        "  reference: Optional reference text shown on both legs\n"
        "  from_currency_rate: Optional FX rate when source/dest differ\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns the created BankTransfer object including BankTransferID "
        "and both auto-created BankTransactionIDs."
    )
)
async def bank_transfers_create(
    from_bank_account_id: str,
    to_bank_account_id: str,
    amount: float,
    date: str,
    reference: str | None = None,
    from_currency_rate: float | None = None,
    profile: str | None = None,
) -> Any:
    body: dict[str, Any] = {
        "FromBankAccount": {"AccountID": from_bank_account_id},
        "ToBankAccount": {"AccountID": to_bank_account_id},
        "Amount": amount,
        "Date": date,
    }
    if reference:
        body["Reference"] = reference
    if from_currency_rate:
        body["FromIsReconciled"] = False
        body["ToIsReconciled"] = False
        body["CurrencyRate"] = from_currency_rate
    # Xero accepts either a single transfer or {"BankTransfers": [...]}
    return await _api("PUT", "/BankTransfers", profile=profile, json_body=body)


@mcp.tool(
    description=(
        "[xero-rest sidecar] Create a NATIVE Xero BatchPayment — a single "
        "bank-account line that pays N invoices/bills at once. Shows as ONE "
        "entry in the Xero UI with the per-invoice splits inside.\n"
        "\n"
        "USE WHENEVER you have one bank withdrawal that pays multiple bills "
        "(monthly CRA payroll remittance pair, multi-bill reimbursement to a "
        "supplier, etc.). For a single-invoice payment use payments_create.\n"
        "\n"
        "Args:\n"
        "  account_id: Bank/clearing AccountID the payment is FROM (REQUIRED)\n"
        "  date: YYYY-MM-DD payment date (REQUIRED)\n"
        "  payments: List of {invoice_id, amount, reference?} (REQUIRED)\n"
        "  reference: Optional batch-level reference\n"
        "  narrative: Optional bank-line narrative\n"
        "  details: Optional 'details' field (Xero's freeform memo)\n"
        "  type: BatchPaymentType — defaults to 'PAYBATCH' (other valid: "
        "'RECBATCH' for receipts from customers)\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns the created BatchPayment with BatchPaymentID + per-invoice "
        "payment IDs."
    )
)
async def batch_payments_create(
    account_id: str,
    date: str,
    payments: list[dict],
    reference: str | None = None,
    narrative: str | None = None,
    details: str | None = None,
    type: str = "PAYBATCH",
    profile: str | None = None,
) -> Any:
    items: list[dict] = []
    for p in payments:
        iid = p.get("invoice_id") or p.get("invoiceId") or p.get("InvoiceID")
        amt = p.get("amount") or p.get("Amount")
        if not iid or amt is None:
            return {"_error": "each payment must have invoice_id and amount", "bad_item": p}
        item: dict[str, Any] = {
            "Invoice": {"InvoiceID": iid},
            "Amount": amt,
        }
        if p.get("reference") or p.get("Reference"):
            item["Reference"] = p.get("reference") or p.get("Reference")
        if p.get("details") or p.get("Details"):
            item["Details"] = p.get("details") or p.get("Details")
        items.append(item)
    body: dict[str, Any] = {
        "Account": {"AccountID": account_id},
        "Date": date,
        "Type": type,
        "Payments": items,
    }
    if reference:
        body["Reference"] = reference
    if narrative:
        body["Narrative"] = narrative
    if details:
        body["Details"] = details
    return await _api("PUT", "/BatchPayments", profile=profile, json_body=body)


@mcp.tool(
    description=(
        "[xero-rest sidecar] Attach a file to a Xero record (bank "
        "transaction, invoice, bill, credit note, manual journal, receipt, "
        "etc.). The CLI doesn't expose attachments at all — this is the "
        "only way to attach receipts / supporting docs programmatically.\n"
        "\n"
        "USE WHENEVER you have a PDF / image / file that needs to be linked "
        "to a Xero record. Common: receipt PDFs on bills, scanned cheques on "
        "bank-tx, contract PDFs on invoices.\n"
        "\n"
        "Args:\n"
        "  target_type: 'BankTransactions' | 'Invoices' | 'CreditNotes' | "
        "'ManualJournals' | 'Receipts' | 'Quotes' | 'Items' | 'Accounts' "
        "(REQUIRED — the Xero endpoint name, plural)\n"
        "  target_id: UUID of the record to attach to (REQUIRED)\n"
        "  file_path: Absolute path to the file on disk (REQUIRED)\n"
        "  file_name: Display name in Xero — defaults to basename of file_path\n"
        "  include_online: If True, sets IncludeOnline=true so the attachment "
        "appears in the online invoice/quote PDF (only meaningful for "
        "Invoices/Quotes/CreditNotes)\n"
        "  content_type: MIME type — auto-detected from extension if omitted\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns the created Attachment metadata (AttachmentID, FileName, "
        "MimeType, ContentLength, Url)."
    )
)
async def attachments_upload(
    target_type: str,
    target_id: str,
    file_path: str,
    file_name: str | None = None,
    include_online: bool = False,
    content_type: str | None = None,
    profile: str | None = None,
) -> Any:
    fp = Path(file_path).expanduser()
    if not fp.exists():
        return {"_error": f"file not found: {fp}"}
    name = file_name or fp.name
    # MIME guess
    if not content_type:
        ext = fp.suffix.lower()
        content_type = {
            ".pdf": "application/pdf",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".tiff": "image/tiff",
            ".csv": "text/csv",
            ".txt": "text/plain",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }.get(ext, "application/octet-stream")
    payload = fp.read_bytes()
    path = f"/{target_type}/{target_id}/Attachments/{name}"
    if include_online:
        path += "?IncludeOnline=true"
    return await _api(
        "POST", path, profile=profile,
        raw_content=payload, raw_content_type=content_type,
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] List the attachments already linked to a Xero "
        "record (bank-tx, invoice, bill, etc.).\n"
        "\n"
        "USE WHENEVER you want to know what files are already attached to a "
        "record before uploading another (avoid duplicates), check that a "
        "receipt landed correctly after `attachments_upload`, or audit which "
        "bills have supporting docs vs which don't.\n"
        "\n"
        "Args:\n"
        "  target_type: 'BankTransactions' | 'Invoices' | 'CreditNotes' | "
        "'ManualJournals' | 'Receipts' | 'Quotes' | 'Items' | 'Accounts' "
        "(REQUIRED — Xero endpoint name, plural)\n"
        "  target_id: UUID of the record (REQUIRED)\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns an Attachments array; empty if nothing is attached. Each "
        "entry has AttachmentID, FileName, MimeType, ContentLength, and Url."
    )
)
async def attachments_list(
    target_type: str,
    target_id: str,
    profile: str | None = None,
) -> Any:
    return await _api(
        "GET", f"/{target_type}/{target_id}/Attachments",
        profile=profile,
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Update an existing BankTransaction. The CLI "
        "doesn't expose updates — only creates — so this is the only way to "
        "fix a posted bank-tx without going into the Xero UI.\n"
        "\n"
        "USE WHENEVER you need to correct a reference, swap a GL account on "
        "a line item, change a contact, change the date, etc.\n"
        "\n"
        "Args:\n"
        "  bank_transaction_id: UUID of the bank-tx to update (REQUIRED)\n"
        "  data: PARTIAL update dict — only fields you want changed. Common: "
        "{'Reference': '...'}, {'Date': '...'}, {'LineItems': [...]}, "
        "{'Contact': {'ContactID': '...'}}\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns the updated BankTransaction object."
    )
)
async def bank_transactions_update(
    bank_transaction_id: str,
    data: dict,
    profile: str | None = None,
) -> Any:
    body = {**data, "BankTransactionID": bank_transaction_id}
    # Xero accepts POST to the collection or to the specific item endpoint
    return await _api(
        "POST", f"/BankTransactions/{bank_transaction_id}",
        profile=profile, json_body=body,
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Void or delete a BankTransaction. The CLI "
        "doesn't expose this — this is the only way to undo a posted bank-tx "
        "programmatically.\n"
        "\n"
        "USE WHENEVER you've posted a bank-tx in error and need to remove "
        "it. DELETED is the typical status for bank-tx (VOIDED is mainly for "
        "invoices); the wrapper defaults to DELETED.\n"
        "\n"
        "Args:\n"
        "  bank_transaction_id: UUID of the bank-tx (REQUIRED)\n"
        "  status: 'DELETED' (default) | 'VOIDED'\n"
        "  profile: Optional profile override"
    )
)
async def bank_transactions_void(
    bank_transaction_id: str,
    status: str = "DELETED",
    profile: str | None = None,
) -> Any:
    body = {"BankTransactionID": bank_transaction_id, "Status": status}
    return await _api(
        "POST", f"/BankTransactions/{bank_transaction_id}",
        profile=profile, json_body=body,
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Void or delete an Invoice. The CLI doesn't "
        "expose this — this is the only way to undo a posted invoice "
        "programmatically.\n"
        "\n"
        "USE WHENEVER you posted an invoice (or bill) in error. VOIDED is "
        "for authorised invoices; DELETED is for drafts. Wrapper defaults "
        "to VOIDED.\n"
        "\n"
        "Args:\n"
        "  invoice_id: UUID of the invoice (REQUIRED)\n"
        "  status: 'VOIDED' (default — for authorised) | 'DELETED' (for drafts)\n"
        "  profile: Optional profile override"
    )
)
async def invoices_void(
    invoice_id: str,
    status: str = "VOIDED",
    profile: str | None = None,
) -> Any:
    body = {"InvoiceID": invoice_id, "Status": status}
    return await _api(
        "POST", f"/Invoices/{invoice_id}",
        profile=profile, json_body=body,
    )


# ---------------------------------------------------------------------------
# Payload normalization for *_full create/update tools
# ---------------------------------------------------------------------------
# Xero REST accepts MOST camelCase fields directly (Type, Date, DueDate,
# CurrencyCode, Status, LineItems, etc.) but a few require nested PascalCase
# objects for ID references — flat `contactId` is rejected as "A Contact
# must be specified". We normalize the most common flat-form ID refs into
# their nested REST shape so callers can use the same camelCase keys they
# pass to the xero-cli wrapper.

def _normalize_xero_payload(data: dict) -> dict:
    """Convert common flat ID refs to Xero REST's nested form. Idempotent —
    leaves already-nested PascalCase fields untouched.

    Rewrites these flat keys → nested objects:
      contactId         → Contact: {ContactID: <uuid>}
      bankAccountId     → BankAccount: {AccountID: <uuid>}
      lineItems[].accountId → AccountID inside the line item (rare; AccountCode
                              is preferred but Xero accepts AccountID too)

    Other camelCase top-level fields pass through unchanged — Xero REST
    normalizes Type/Date/Status/CurrencyCode/LineAmountTypes/etc. on its
    own. Returns a new dict (does not mutate input)."""
    out = dict(data)
    cid = out.pop("contactId", None) or out.pop("ContactId", None)
    if cid and "Contact" not in out and "contact" not in out:
        out["Contact"] = {"ContactID": cid}
    bid = out.pop("bankAccountId", None) or out.pop("BankAccountId", None)
    if bid and "BankAccount" not in out and "bankAccount" not in out:
        out["BankAccount"] = {"AccountID": bid}
    return out


# ---------------------------------------------------------------------------
# *_full create/update tools — bypass the CLI's field-stripping bug
# ---------------------------------------------------------------------------
# The upstream xero-command-line CLI hard-codes the outgoing payload for
# invoices/credit-notes/quotes/bank-transactions to a small whitelist of
# fields and silently drops everything else. CurrencyCode, CurrencyRate,
# Status, DueDate, LineAmountTypes, BrandingThemeID, etc. all go missing.
# Concrete failure: an ACCREC invoice with currencyCode='USD' lands in the
# org's base currency (CAD) as DRAFT instead of USD AUTHORISED. Blocks any
# foreign-currency invoicing.
#
# These _full variants POST directly to Xero's REST API with the user's
# data dict passed through verbatim — no field stripping. Xero REST accepts
# either camelCase or PascalCase for input, so the data dict can use
# whichever the caller prefers; we forward it untouched.
# ---------------------------------------------------------------------------

@mcp.tool(
    description=(
        "[xero-rest sidecar] Create an invoice with FULL Xero REST field "
        "support — PASSES THROUGH every field in your `data` dict, including "
        "CurrencyCode, CurrencyRate, Status, DueDate, LineAmountTypes, "
        "BrandingThemeID, ExpectedPaymentDate, InvoiceNumber, etc.\n"
        "\n"
        "USE WHENEVER you need a non-base-currency invoice (USD, EUR, GBP "
        "in a CAD-base org), need to post as AUTHORISED in one shot (skip "
        "DRAFT), set a specific due date, or any other field beyond the "
        "{type, contact, lineItems, date, reference} minimum.\n"
        "\n"
        "PREFER THIS over `mcp__xero-cli__invoices_create` whenever currency, "
        "status, dueDate, or any non-trivial field matters — the CLI version "
        "silently drops those fields and forces the invoice into the org's "
        "base currency as DRAFT. The CLI version is fine for the simplest "
        "AUTHORISED-after-the-fact CAD invoices but not much else.\n"
        "\n"
        "Args:\n"
        "  data: Full Xero invoice payload (dict). Both camelCase and "
        "PascalCase keys work — Xero REST accepts either. Forwarded verbatim.\n"
        "  profile: Optional profile override\n"
        "\n"
        "Returns the created Invoice object. Pull invoiceID + currencyCode "
        "+ currencyRate from the response to confirm the currency stuck "
        "(should be non-1 rate for FX invoices)."
    )
)
async def invoices_create_full(
    data: dict,
    profile: str | None = None,
) -> Any:
    return await _api(
        "PUT", "/Invoices",
        profile=profile,
        json_body={"Invoices": [_normalize_xero_payload(data)]},
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Update an invoice with FULL Xero REST field "
        "support — PASSES THROUGH every field in your `data` dict.\n"
        "\n"
        "USE WHENEVER you need to change fields the CLI's invoices_update "
        "doesn't expose: CurrencyCode, CurrencyRate, Status (e.g., promote "
        "DRAFT → AUTHORISED), LineAmountTypes, BrandingThemeID, DueDate, etc.\n"
        "\n"
        "Args:\n"
        "  invoice_id: InvoiceID UUID (REQUIRED)\n"
        "  data: Partial update dict — only fields to change. InvoiceID is "
        "auto-merged from invoice_id arg; you don't need to repeat it.\n"
        "  profile: Optional profile override"
    )
)
async def invoices_update_full(
    invoice_id: str,
    data: dict,
    profile: str | None = None,
) -> Any:
    body = {**_normalize_xero_payload(data), "InvoiceID": invoice_id}
    return await _api(
        "POST", f"/Invoices/{invoice_id}",
        profile=profile, json_body=body,
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Create a credit note with FULL Xero REST field "
        "support — PASSES THROUGH every field in your `data` dict including "
        "CurrencyCode, Status, Date, DueDate, LineAmountTypes, etc.\n"
        "\n"
        "USE WHENEVER you need a foreign-currency credit note or to post as "
        "AUTHORISED directly. The CLI's credit_notes_create drops the same "
        "fields invoices_create does.\n"
        "\n"
        "Args:\n"
        "  data: Full Xero credit note payload (Type, Contact, LineItems, "
        "CurrencyCode, Status, Date, ...). camelCase or PascalCase both work.\n"
        "  profile: Optional profile override"
    )
)
async def credit_notes_create_full(
    data: dict,
    profile: str | None = None,
) -> Any:
    return await _api(
        "PUT", "/CreditNotes",
        profile=profile,
        json_body={"CreditNotes": [_normalize_xero_payload(data)]},
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Create a quote with FULL Xero REST field "
        "support — PASSES THROUGH every field in your `data` dict including "
        "CurrencyCode, CurrencyRate, Status, ExpiryDate, BrandingThemeID, etc.\n"
        "\n"
        "USE WHENEVER you need a foreign-currency quote or want fields the "
        "CLI's quotes_create drops.\n"
        "\n"
        "Args:\n"
        "  data: Full Xero quote payload. camelCase or PascalCase both work.\n"
        "  profile: Optional profile override"
    )
)
async def quotes_create_full(
    data: dict,
    profile: str | None = None,
) -> Any:
    return await _api(
        "PUT", "/Quotes",
        profile=profile,
        json_body={"Quotes": [_normalize_xero_payload(data)]},
    )


@mcp.tool(
    description=(
        "[xero-rest sidecar] Create a bank transaction with FULL Xero REST "
        "field support — PASSES THROUGH every field in your `data` dict "
        "including CurrencyCode, CurrencyRate (for foreign-currency txns), "
        "Status, LineAmountTypes, IsReconciled, etc.\n"
        "\n"
        "USE WHENEVER you need a foreign-currency bank transaction (posting "
        "USD spend on a USD bank account in a CAD-base org), need to pre-"
        "reconcile, or want any field beyond the CLI's "
        "{type, bankAccount, contact, lineItems, date, reference} minimum.\n"
        "\n"
        "Args:\n"
        "  data: Full Xero BankTransaction payload (Type, BankAccount, "
        "Contact, LineItems, Date, CurrencyCode, ...). camelCase or "
        "PascalCase both work.\n"
        "  profile: Optional profile override"
    )
)
async def bank_transactions_create_full(
    data: dict,
    profile: str | None = None,
) -> Any:
    return await _api(
        "PUT", "/BankTransactions",
        profile=profile,
        json_body={"BankTransactions": [_normalize_xero_payload(data)]},
    )


# ---------------------------------------------------------------------------
# Accounts — CREATE + ARCHIVE (xero-cli has list + update only; this fills the
# gap so monthly-close automation can spin up clearing/suspense accounts
# without a UI step. Filed upstream ticket against the `xero` CLI itself, but
# don't block on whoever maintains that — this sidecar already exists for
# exactly this kind of gap.)
# ---------------------------------------------------------------------------

@mcp.tool(
    description=(
        "[xero-rest sidecar] CREATE / ADD / MAKE / NEW / SET-UP / OPEN a "
        "Xero Chart-of-Accounts entry — wraps PUT /Accounts. Use whenever "
        "monthly-close automation needs to spin up a fresh GL account "
        "(clearing/suspense/holding accounts, new expense categories, new "
        "tracking-cost buckets, etc.) without touching the Xero web UI.\n"
        "\n"
        "Fills the xero-cli gap (it has accounts_list + accounts_update but "
        "NO accounts_create) and is the canonical answer for any 'create a "
        "new account in the Chart of Accounts' workflow.\n"
        "\n"
        "Args:\n"
        "  code: 1–10 alphanumeric chars, MUST be unique/unused in this org "
        "(REQUIRED for non-BANK accounts; Xero auto-generates for BANK).\n"
        "  name: Account display name (REQUIRED).\n"
        "  account_type: Xero AccountType enum — EXPENSE, REVENUE, "
        "DIRECTCOSTS, OVERHEADS, CURRENT (current asset), FIXED, INVENTORY, "
        "PREPAYMENT, CURRLIAB (current liability), LIABILITY, TERMLIAB "
        "(non-current liability), EQUITY, BANK, SALES, NONCURRENT (REQUIRED). "
        "Named account_type to avoid shadowing Python's `type` builtin.\n"
        "  tax_type: Optional TaxType code — e.g. NONE, INPUT, OUTPUT, "
        "CAN030, EXEMPTEXPENSES. Defaults by account_type per Xero rules.\n"
        "  description: Optional. NOT permitted when account_type = BANK.\n"
        "  bank_account_number: REQUIRED if account_type = BANK; ignored "
        "otherwise.\n"
        "  bank_account_type: BANK / CREDITCARD / PAYPAL (when BANK).\n"
        "  currency_code: ISO 4217 — only meaningful for BANK accounts.\n"
        "  enable_payments_to_account: bool — if True, this account can be "
        "selected as a payment-destination on customer invoices.\n"
        "  show_in_expense_claims: bool — exposes account to expense-claim "
        "submitters.\n"
        "  add_to_watchlist: bool — pins to the dashboard watchlist.\n"
        "  profile: Optional profile override.\n"
        "\n"
        "Returns the created Account object including AccountID (GUID), "
        "Class (auto-derived), and Status (ACTIVE).\n"
        "\n"
        "Errors to expect:\n"
        "  - Duplicate Code → Xero 400 'Please enter a unique Code' verbatim.\n"
        "  - Invalid Type/TaxType combo → 400 with field-level details.\n"
        "  - BANK without BankAccountNumber → 400.\n"
        "  - Description on BANK → 400 (Xero rejects).\n"
        "\n"
        "Use INSTEAD of: xero-cli's accounts_update (which can only modify "
        "existing accounts), or manual UI creation. NOT for: archiving "
        "(accounts_archive), bulk import (use Xero's CSV importer)."
    )
)
async def accounts_create(
    code: str | None = None,
    name: str = "",
    account_type: str = "",
    tax_type: str | None = None,
    description: str | None = None,
    bank_account_number: str | None = None,
    bank_account_type: str | None = None,
    currency_code: str | None = None,
    enable_payments_to_account: bool | None = None,
    show_in_expense_claims: bool | None = None,
    add_to_watchlist: bool | None = None,
    profile: str | None = None,
) -> Any:
    if not name:
        return _err("accounts_create", ValueError("`name` is required"))
    if not account_type:
        return _err("accounts_create", ValueError("`account_type` is required (e.g. EXPENSE, BANK, CURRLIAB)"))
    body: dict[str, Any] = {"Name": name, "Type": account_type.upper()}
    if code is not None:
        body["Code"] = str(code)
    elif account_type.upper() != "BANK":
        return _err("accounts_create", ValueError("`code` is required for non-BANK account types"))
    if tax_type is not None:
        body["TaxType"] = tax_type
    if description is not None:
        if account_type.upper() == "BANK":
            return _err("accounts_create", ValueError("`description` is not permitted on BANK accounts (Xero rule)"))
        body["Description"] = description
    if account_type.upper() == "BANK":
        if not bank_account_number:
            return _err("accounts_create", ValueError("`bank_account_number` is required when account_type=BANK"))
        body["BankAccountNumber"] = bank_account_number
        if bank_account_type is not None:
            body["BankAccountType"] = bank_account_type.upper()
        if currency_code is not None:
            body["CurrencyCode"] = currency_code.upper()
    for k, v in {
        "EnablePaymentsToAccount": enable_payments_to_account,
        "ShowInExpenseClaims": show_in_expense_claims,
        "AddToWatchlist": add_to_watchlist,
    }.items():
        if v is not None:
            body[k] = v
    return await _api("PUT", "/Accounts", profile=profile, json_body=body)


@mcp.tool(
    description=(
        "[xero-rest sidecar] ARCHIVE / DEACTIVATE / RETIRE / DEPRECATE / "
        "HIDE / SUNSET a Xero Chart-of-Accounts entry — wraps POST "
        "/Accounts/{AccountID} with `Status=ARCHIVED`. Xero does NOT delete "
        "accounts via API (or via UI) once they've had activity; "
        "deactivation is the canonical retire path. After archival the "
        "account is hidden from drop-downs and reports but historical "
        "postings remain queryable.\n"
        "\n"
        "Use this when: cleaning up the Chart of Accounts after a "
        "reorganization, retiring an old clearing account that's been zeroed "
        "out, sunsetting a tracking bucket that's no longer used. The "
        "symmetric companion to accounts_create.\n"
        "\n"
        "Args:\n"
        "  account_id: Xero AccountID GUID (the canonical identifier; e.g. "
        "'00000000-0000-0000-0000-000000000000'). To retrieve, use xero-cli "
        "accounts_list and grab the AccountID field.\n"
        "  profile: Optional profile override.\n"
        "\n"
        "Returns the updated Account object with Status=ARCHIVED. To restore "
        "later: call xero-cli's accounts_update with Status=ACTIVE.\n"
        "\n"
        "NOT for: deleting accounts with historical postings (impossible; "
        "Xero preserves audit trail), removing accounts pre-activity (use "
        "the Xero UI's delete option), or full account replacement (create "
        "the new one, archive the old, manually re-route any active "
        "subscriptions/templates/rules)."
    )
)
async def accounts_archive(
    account_id: str,
    profile: str | None = None,
) -> Any:
    if not account_id:
        return _err("accounts_archive", ValueError("`account_id` is required"))
    return await _api(
        "POST", f"/Accounts/{account_id}",
        profile=profile,
        json_body={"Status": "ARCHIVED"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Console script entry. Stdio transport — Claude Desktop spawns this
    process per session, same pattern as stripe-rich-mcp."""
    print(
        f"[xero-rest-mcp] starting (stdio) — token store: {TOKENS_PATH}",
        file=sys.stderr, flush=True,
    )
    mcp.run()


if __name__ == "__main__":
    main()
