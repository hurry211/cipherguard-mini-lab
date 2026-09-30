import json
import unittest

from cipherguard.core import DecryptionError, decrypt_bytes, encrypt_bytes, generate_signing_key, sign_bytes, verify_bytes


class CoreTests(unittest.TestCase):
    def test_authenticated_encryption_round_trip(self):
        plaintext = "国密与应用安全实验".encode()
        payload = encrypt_bytes(plaintext, "team-password-2026")
        self.assertEqual(decrypt_bytes(payload, "team-password-2026"), plaintext)

    def test_fresh_nonce_changes_ciphertext(self):
        first = encrypt_bytes(b"same", "team-password-2026")
        second = encrypt_bytes(b"same", "team-password-2026")
        self.assertNotEqual(json.loads(first)["nonce"], json.loads(second)["nonce"])
        self.assertNotEqual(first, second)

    def test_tampering_is_rejected(self):
        envelope = json.loads(encrypt_bytes(b"secret", "team-password-2026"))
        envelope["ciphertext"] = envelope["ciphertext"][:-2] + "AA"
        with self.assertRaises(DecryptionError):
            decrypt_bytes(json.dumps(envelope).encode(), "team-password-2026")

    def test_signature_detects_change(self):
        private, public = generate_signing_key()
        signature = sign_bytes(b"message", private)
        self.assertTrue(verify_bytes(b"message", signature, public))
        self.assertFalse(verify_bytes(b"changed", signature, public))


if __name__ == "__main__":
    unittest.main()

