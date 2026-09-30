import unittest

from cipherguard.audit import audit_config


class AuditTests(unittest.TestCase):
    def test_insecure_configuration_is_detected(self):
        findings = audit_config({
            "encryption_algorithm": "DES",
            "block_mode": "ECB",
            "minimum_tls": "1.0",
            "hardcoded_key": True,
            "audit_logging": False,
            "certificate_validation": False,
        })
        codes = {item.code for item in findings}
        self.assertEqual(codes, {"CG-A01", "CG-A02", "CG-P01", "CG-K01", "CG-K02", "CG-O01", "CG-P02"})

    def test_reasonable_configuration_has_no_findings(self):
        findings = audit_config({
            "encryption_algorithm": "AES",
            "block_mode": "GCM",
            "minimum_tls": "1.3",
            "hardcoded_key": False,
            "key_rotation_days": 90,
            "audit_logging": True,
            "certificate_validation": True,
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

