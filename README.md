# TensorHost Mail-MCP releases

This public repository is the independent release channel for TensorHost's
Mail-MCP installer. Installer code is public already; mailbox credentials are
never stored here.

## Install

Copy the command for your assistant from this GitHub page, not from a portal
page. The first install trusts this public GitHub repository and its immutable
bootstrap commit. The verified bootstrap installs a local `update.py`; use that
local verifier for later updates so a future portal-origin compromise cannot
replace the update path.

Claude Code:

```bash
(tmp=$(mktemp) && trap 'rm -f "$tmp"' EXIT && curl -fsSL https://raw.githubusercontent.com/TensorHost/mail-mcp-releases/453bc455dc5284895ad04e1c45024ef19571e910/bootstrap.py -o "$tmp" && python3 "$tmp" --target claude)
```

Gemini CLI:

```bash
(tmp=$(mktemp) && trap 'rm -f "$tmp"' EXIT && curl -fsSL https://raw.githubusercontent.com/TensorHost/mail-mcp-releases/453bc455dc5284895ad04e1c45024ef19571e910/bootstrap.py -o "$tmp" && python3 "$tmp" --target gemini)
```

`bootstrap.py` pins the operator-held root public key. It verifies the root-signed
release-key delegation, the release-signed manifest, and the exact target
installer before execution. It also stores the highest accepted release
sequence and trust-delegation version locally and rejects release rollback,
delegation rollback, or same-sequence equivocation.

The private portal repository publishes `current/` through a repository-scoped
publisher credential. The operator-held root private key and online release private key must
never be committed to either repository.

Every published installer is checked for literal mailbox credentials, mailbox
addresses, credential-bearing SMTP URLs, and private-key material. GitHub secret
scanning and push protection are also enabled on this public release channel.

## Verify without executing

```bash
python3 bootstrap.py --target claude --download-only ./install-claude.sh
python3 bootstrap.py --target gemini --download-only ./install-gemini.sh
```

## Rotation and revocation

1. Generate a new release key outside both repositories.
2. Create a canonical `trust/delegation.json` with a higher `version`, the new
   public key and key ID, and the old key ID in `revoked_release_key_ids` when
   revocation is required.
3. Sign the exact delegation bytes with the operator-held root private key.
4. Update the portal release-environment secret before publishing another
   release, then commit the delegation and signature here.
5. Preserve the old signed delegation and incident evidence outside `main`.

Root-key replacement requires a new independently distributed bootstrap and is
an attended recovery operation.
