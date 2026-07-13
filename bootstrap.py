#!/usr/bin/env python3
"""Verify and run a TensorHost Mail-MCP installer release."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


REPOSITORY = "TensorHost/mail-mcp-releases"
RAW_BASE = f"https://raw.githubusercontent.com/{REPOSITORY}/main"
ROOT_KEY_ID = "sha256:e0939653dc7c774f72435e9e675c254df8cc9143914348a1486691af9ae24131"
ROOT_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzVmIdWBvF3o0AFD3/OxL
ANvAtnKSgVFz/P//YW2h65RpUSI4jozZo3j+6meyEVqqTWhYYT6OKk8tZxqEnUNA
1dZVUH7ivLfobPTgh7xQpHkeFRgFy+90FQc/4+mznHuBECBR9FRX5kr1z/e6QpWE
NDCkw2mLNH/YxY+7XstNOXlxH3aJcrDLDPagmUcoCIwDIeT3dcTYGjYl3uoUEu6h
N7v9OXpKwl14qcJIH5TCXRqnPnSSdqm0FFdAimO+4nG0+yLtxis5+Z8WeE/ys4yT
Iqno3g5n1gCCyMLl3aSzHLyMk/R78whGJctan5C/6QWDL2lR+7mZNVMHPzj5rkYC
F8w/bJjb3GZXAINzBn+lP0xx6apcG/q/t7xtDXeIizcDy2o/Jjy8N6zWEnNyLGAC
o4pnUWJ0Mp6RWUX1SCgrFwda/b6Ua8pVyGy0iR7GCCjE6BT7KYJ2+WjJgZpR16NM
ZhwHp7z1zwjut399lEvZRaDnj0Jh6P9GCW4nQJU5nXzTAgMBAAE=
-----END PUBLIC KEY-----
"""
MAX_METADATA_BYTES = 64 * 1024
MAX_INSTALLER_BYTES = 2 * 1024 * 1024
EXPECTED_FILES = {"claude": "install-claude.sh", "gemini": "install-gemini.sh"}


class VerificationError(RuntimeError):
    pass


def _json_no_duplicates(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("invalid signed JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError("signed JSON must be an object")
    return value


def _require_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise VerificationError(f"unexpected {label} fields")


def _parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError("invalid UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerificationError("invalid UTC timestamp") from exc
    return parsed


def _verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise VerificationError("OpenSSL is required to verify this release")
    with tempfile.TemporaryDirectory(prefix="tensorhost-mail-mcp-verify-") as tmp:
        root = pathlib.Path(tmp)
        key_path = root / "key.pem"
        payload_path = root / "payload"
        signature_path = root / "signature"
        key_path.write_bytes(public_key)
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        proc = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(key_path),
             "-signature", str(signature_path), str(payload_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if proc.returncode != 0:
        raise VerificationError("release signature verification failed")


def _public_key_id(public_key: bytes) -> str:
    openssl = shutil.which("openssl")
    if not openssl:
        raise VerificationError("OpenSSL is required to verify this release")
    proc = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "DER"],
        input=public_key,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0:
        raise VerificationError("delegated release key is invalid")
    return "sha256:" + hashlib.sha256(proc.stdout).hexdigest()


def verify_release(
    delegation_raw: bytes,
    delegation_signature: bytes,
    manifest_raw: bytes,
    manifest_signature: bytes,
    installer: bytes,
    target: str,
    *,
    root_public_key: bytes = ROOT_PUBLIC_KEY,
    root_key_id: str = ROOT_KEY_ID,
    now: dt.datetime | None = None,
) -> tuple[dict, str, int]:
    now = now or dt.datetime.now(dt.timezone.utc)
    _verify_signature(root_public_key, delegation_raw, delegation_signature)
    delegation = _json_no_duplicates(delegation_raw)
    _require_keys(
        delegation,
        {"expires", "format", "release_key", "revoked_release_key_ids", "root_key_id", "version"},
        "delegation",
    )
    if delegation["format"] != 1 or delegation["root_key_id"] != root_key_id:
        raise VerificationError("unsupported trust delegation")
    if not isinstance(delegation["version"], int) or delegation["version"] < 1:
        raise VerificationError("invalid delegation version")
    if _parse_time(delegation["expires"]) <= now:
        raise VerificationError("release-key delegation has expired")
    revoked = delegation["revoked_release_key_ids"]
    if not isinstance(revoked, list) or not all(isinstance(item, str) for item in revoked):
        raise VerificationError("invalid release-key revocation list")
    release_key = delegation["release_key"]
    if not isinstance(release_key, dict):
        raise VerificationError("invalid delegated release key")
    _require_keys(release_key, {"id", "pem"}, "release key")
    if not isinstance(release_key["pem"], str):
        raise VerificationError("invalid delegated release key")
    release_public_key = release_key["pem"].encode("ascii", "strict")
    if release_key["id"] != _public_key_id(release_public_key):
        raise VerificationError("delegated release-key fingerprint mismatch")
    if release_key["id"] in revoked:
        raise VerificationError("delegated release key is revoked")

    _verify_signature(release_public_key, manifest_raw, manifest_signature)
    manifest = _json_no_duplicates(manifest_raw)
    _require_keys(
        manifest,
        {"commit", "expires", "format", "published_at", "release_key_id", "sequence", "targets"},
        "manifest",
    )
    if manifest["format"] != 1 or manifest["release_key_id"] != release_key["id"]:
        raise VerificationError("unsupported or wrongly bound release manifest")
    if not isinstance(manifest["sequence"], int) or manifest["sequence"] < 1:
        raise VerificationError("invalid release sequence")
    if not isinstance(manifest["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]):
        raise VerificationError("invalid source commit")
    published = _parse_time(manifest["published_at"])
    expires = _parse_time(manifest["expires"])
    if expires <= now or published > now + dt.timedelta(minutes=10) or expires <= published:
        raise VerificationError("release manifest is expired or has invalid dates")
    targets = manifest["targets"]
    if not isinstance(targets, dict) or set(targets) != set(EXPECTED_FILES):
        raise VerificationError("manifest target set is invalid")
    entry = targets.get(target)
    if not isinstance(entry, dict):
        raise VerificationError("requested target is not signed")
    _require_keys(entry, {"file", "sha256", "size"}, "target")
    if entry["file"] != EXPECTED_FILES[target]:
        raise VerificationError("signed target filename mismatch")
    if not isinstance(entry["size"], int) or entry["size"] < 1 or entry["size"] > MAX_INSTALLER_BYTES:
        raise VerificationError("signed target size is invalid")
    digest = hashlib.sha256(installer).hexdigest()
    if len(installer) != entry["size"] or entry["sha256"] != digest:
        raise VerificationError("installer bytes do not match the signed manifest")
    return manifest, hashlib.sha256(manifest_raw).hexdigest(), delegation["version"]


def _download(relative: str, limit: int) -> bytes:
    url = f"{RAW_BASE}/{relative}"
    request = urllib.request.Request(url, headers={"User-Agent": "tensorhost-mail-mcp-bootstrap/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
                raise VerificationError("release download left the trusted GitHub origin")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > limit:
                raise VerificationError("release file exceeds its size limit")
            body = response.read(limit + 1)
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError(f"could not download {relative}") from exc
    if len(body) > limit:
        raise VerificationError("release file exceeds its size limit")
    return body


def _state_path() -> pathlib.Path:
    root = pathlib.Path(os.environ.get("TENSORHOST_MAIL_MCP_DIR", "~/.tensorhost/mail-mcp")).expanduser()
    return root / "TRUSTED_RELEASE.json"


def _load_state(path: pathlib.Path) -> dict | None:
    if not path.exists():
        return None
    mode = path.lstat().st_mode
    if path.is_symlink() or not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
        raise VerificationError("trusted-release state must be a regular mode-0600 file")
    state = _json_no_duplicates(path.read_bytes())
    _require_keys(state, {"commit", "delegation_version", "manifest_sha256", "sequence"}, "trusted-release state")
    if not isinstance(state["sequence"], int) or state["sequence"] < 1:
        raise VerificationError("trusted-release state is invalid")
    if not isinstance(state["delegation_version"], int) or state["delegation_version"] < 1:
        raise VerificationError("trusted-release delegation state is invalid")
    return state


def _check_rollback(state: dict | None, manifest: dict, manifest_digest: str, delegation_version: int) -> None:
    if state is None:
        return
    if delegation_version < state["delegation_version"]:
        raise VerificationError("refusing an older release-key delegation")
    if manifest["sequence"] < state["sequence"]:
        raise VerificationError("refusing to install an older signed release")
    if manifest["sequence"] == state["sequence"] and manifest_digest != state["manifest_sha256"]:
        raise VerificationError("refusing conflicting manifests for one release sequence")


def _write_state(path: pathlib.Path, manifest: dict, manifest_digest: str, delegation_version: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "commit": manifest["commit"],
            "delegation_version": delegation_version,
            "manifest_sha256": manifest_digest,
            "sequence": manifest["sequence"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode() + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=".TRUSTED_RELEASE.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _install_updater(path: pathlib.Path) -> None:
    source = pathlib.Path(__file__)
    mode = source.lstat().st_mode
    if source.is_symlink() or not stat.S_ISREG(mode):
        raise VerificationError("bootstrap source must be a regular file")
    body = source.read_bytes()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".update.", suffix=".py", dir=path.parent)
    try:
        os.fchmod(fd, 0o700)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(EXPECTED_FILES), default="claude")
    parser.add_argument("--download-only", metavar="PATH", help="verify and save instead of executing")
    parser.add_argument("installer_args", nargs=argparse.REMAINDER, help="arguments after -- are passed to the installer")
    args = parser.parse_args(argv)
    installer_args = args.installer_args
    if installer_args[:1] == ["--"]:
        installer_args = installer_args[1:]
    try:
        delegation_raw = _download("trust/delegation.json", MAX_METADATA_BYTES)
        delegation_signature = _download("trust/delegation.sig", MAX_METADATA_BYTES)
        manifest_raw = _download("current/manifest.json", MAX_METADATA_BYTES)
        manifest_signature = _download("current/manifest.sig", MAX_METADATA_BYTES)
        installer = _download(f"current/{EXPECTED_FILES[args.target]}", MAX_INSTALLER_BYTES)
        manifest, manifest_digest, delegation_version = verify_release(
            delegation_raw,
            delegation_signature,
            manifest_raw,
            manifest_signature,
            installer,
            args.target,
        )
        state_path = _state_path()
        state = _load_state(state_path)
        _check_rollback(state, manifest, manifest_digest, delegation_version)
        if args.download_only:
            output = pathlib.Path(args.download_only)
            output.write_bytes(installer)
            output.chmod(0o700)
            print(f"Verified release {manifest['sequence']} and wrote {output}")
            return 0
        updater_path = state_path.parent / "update.py"
        _install_updater(updater_path)
        with tempfile.NamedTemporaryFile(prefix="tensorhost-mail-mcp-", suffix=".sh", delete=False) as stream:
            stream.write(installer)
            installer_path = pathlib.Path(stream.name)
        try:
            installer_path.chmod(0o700)
            completed = subprocess.run(["bash", str(installer_path), *installer_args], check=False)
            if completed.returncode != 0:
                return completed.returncode
        finally:
            installer_path.unlink(missing_ok=True)
        _write_state(state_path, manifest, manifest_digest, delegation_version)
        print(f"Verified TensorHost Mail-MCP release {manifest['sequence']} ({manifest['commit'][:12]}).")
        print(f"Future updates: python3 {updater_path} --target {args.target}")
        return 0
    except VerificationError as exc:
        print(f"Mail-MCP verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
