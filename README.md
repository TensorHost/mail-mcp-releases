# TensorHost Mail-MCP releases

This public repository is the independent release channel for TensorHost's
Mail-MCP installer. Installer code is public already; mailbox credentials are
never stored here.

`bootstrap.py` pins the offline root public key. It verifies the root-signed
release-key delegation, the release-signed manifest, and the exact target
installer before execution. It also stores the highest accepted release
sequence locally and rejects rollback or same-sequence equivocation.

The private portal repository publishes `current/` through a repository-scoped
deploy key. The offline root private key and online release private key must
never be committed to either repository.

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
3. Sign the exact delegation bytes with the offline root private key.
4. Update the portal release-environment secret before publishing another
   release, then commit the delegation and signature here.
5. Preserve the old signed delegation and incident evidence outside `main`.

Root-key replacement requires a new independently distributed bootstrap and is
an attended recovery operation.
