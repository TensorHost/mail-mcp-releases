import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

import bootstrap


NOW = dt.datetime(2026, 7, 13, 22, 0, tzinfo=dt.timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class BootstrapVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.tmp.name)
        cls.root_private, cls.root_public = cls._keypair("root")
        cls.release_private, cls.release_public = cls._keypair("release")
        _, cls.other_public = cls._keypair("other")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def _keypair(cls, name):
        private = cls.root / f"{name}-private.pem"
        public = cls.root / f"{name}-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", private],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(["openssl", "pkey", "-in", private, "-pubout", "-out", public], check=True)
        return private, public.read_bytes()

    def _sign(self, private, payload):
        payload_path = self.root / "payload"
        signature_path = self.root / "signature"
        payload_path.write_bytes(payload)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", private, "-out", signature_path, payload_path],
            check=True,
        )
        return signature_path.read_bytes()

    def _fixture(self, sequence=100, installer=b"#!/bin/sh\nexit 0\n"):
        root_id = bootstrap._public_key_id(self.root_public)
        release_id = bootstrap._public_key_id(self.release_public)
        delegation = canonical({
            "expires": "2027-07-13T23:59:59Z",
            "format": 1,
            "release_key": {"id": release_id, "pem": self.release_public.decode()},
            "revoked_release_key_ids": [],
            "root_key_id": root_id,
            "version": 1,
        })
        targets = {}
        for target, filename in bootstrap.EXPECTED_FILES.items():
            body = installer if target == "claude" else b"#!/bin/sh\nexit 1\n"
            targets[target] = {"file": filename, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
        manifest = canonical({
            "commit": "a" * 40,
            "expires": "2027-01-01T00:00:00Z",
            "format": 1,
            "published_at": "2026-07-13T21:55:00Z",
            "release_key_id": release_id,
            "sequence": sequence,
            "targets": targets,
        })
        return root_id, delegation, self._sign(self.root_private, delegation), manifest, self._sign(self.release_private, manifest), installer

    def test_accepts_exact_signed_target(self):
        root_id, delegation, delegation_sig, manifest, manifest_sig, installer = self._fixture()
        parsed, digest, delegation_version = bootstrap.verify_release(
            delegation, delegation_sig, manifest, manifest_sig, installer, "claude",
            root_public_key=self.root_public, root_key_id=root_id, now=NOW,
        )
        self.assertEqual(parsed["sequence"], 100)
        self.assertEqual(digest, hashlib.sha256(manifest).hexdigest())
        self.assertEqual(delegation_version, 1)

    def test_rejects_tampered_installer(self):
        root_id, delegation, delegation_sig, manifest, manifest_sig, installer = self._fixture()
        with self.assertRaisesRegex(bootstrap.VerificationError, "installer bytes"):
            bootstrap.verify_release(
                delegation, delegation_sig, manifest, manifest_sig, installer + b"# tamper\n", "claude",
                root_public_key=self.root_public, root_key_id=root_id, now=NOW,
            )

    def test_rejects_wrong_root(self):
        root_id, delegation, delegation_sig, manifest, manifest_sig, installer = self._fixture()
        with self.assertRaisesRegex(bootstrap.VerificationError, "signature"):
            bootstrap.verify_release(
                delegation, delegation_sig, manifest, manifest_sig, installer, "claude",
                root_public_key=self.other_public, root_key_id=root_id, now=NOW,
            )

    def test_rejects_revoked_release_key(self):
        root_id, delegation, _, manifest, manifest_sig, installer = self._fixture()
        value = json.loads(delegation)
        value["revoked_release_key_ids"] = [value["release_key"]["id"]]
        delegation = canonical(value)
        with self.assertRaisesRegex(bootstrap.VerificationError, "revoked"):
            bootstrap.verify_release(
                delegation, self._sign(self.root_private, delegation), manifest, manifest_sig, installer, "claude",
                root_public_key=self.root_public, root_key_id=root_id, now=NOW,
            )

    def test_rejects_rollback_and_equivocation(self):
        state = {"sequence": 101, "delegation_version": 2, "manifest_sha256": "f" * 64, "commit": "b" * 40}
        manifest = {"sequence": 100}
        with self.assertRaisesRegex(bootstrap.VerificationError, "older"):
            bootstrap._check_rollback(state, manifest, "e" * 64, 2)
        state["sequence"] = 100
        with self.assertRaisesRegex(bootstrap.VerificationError, "conflicting"):
            bootstrap._check_rollback(state, manifest, "e" * 64, 2)
        with self.assertRaisesRegex(bootstrap.VerificationError, "delegation"):
            bootstrap._check_rollback(state, manifest, "f" * 64, 1)


if __name__ == "__main__":
    unittest.main()
