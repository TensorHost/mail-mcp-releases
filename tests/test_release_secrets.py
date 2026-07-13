import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLERS = tuple(sorted((ROOT / "current").glob("install-*.sh")))

FORBIDDEN = {
    "literal mailbox credential assignment": re.compile(
        r"(?m)^\s*(?:MAIL_(?:USER|PASS)|USER|PASS)\s*=\s*['\"](?!\$)[^'\"]+['\"]\s*$"
    ),
    "literal mailbox credential mapping": re.compile(
        r"['\"](?:MAIL_(?:USER|PASS)|user|password)['\"]\s*:\s*['\"][^'\"]+['\"]"
    ),
    "credential-bearing SMTP URL": re.compile(r"(?i)smtps?://[^\s/:]+:[^\s/@]+@"),
    "private key material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "mailbox address literal": re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@(?!example\.(?:com|org|net)\b)[A-Z0-9.-]+\.[A-Z]{2,}\b"
    ),
}


def credential_findings(text):
    return [label for label, pattern in FORBIDDEN.items() if pattern.search(text)]


class ReleaseSecretBoundaryTests(unittest.TestCase):
    def test_release_contains_expected_installers(self):
        self.assertEqual(
            [path.name for path in INSTALLERS],
            ["install-claude.sh", "install-gemini.sh"],
        )

    def test_signed_installer_inputs_contain_no_literal_credentials(self):
        for path in INSTALLERS:
            with self.subTest(path=path.name):
                self.assertEqual(credential_findings(path.read_text()), [])

    def test_detector_rejects_representative_secret_shapes(self):
        samples = (
            'MAIL_PASS="not-a-real-password"',
            '"MAIL_USER": "mailbox@customer.invalid"',
            'smtp://mailbox:password@mail.invalid',
            '-----BEGIN PRIVATE KEY-----',
        )
        for sample in samples:
            with self.subTest(sample=sample.splitlines()[0]):
                self.assertTrue(credential_findings(sample))


if __name__ == "__main__":
    unittest.main()
