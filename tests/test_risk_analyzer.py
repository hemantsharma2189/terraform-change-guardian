import json
import unittest
from pathlib import Path

from risk_analyzer import analyze_plan, create_report


class TestTerraformChangeGuardian(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sample_path = Path("examples/insecure-plan.json")

        with sample_path.open("r", encoding="utf-8") as file:
            cls.plan = json.load(file)

        cls.findings = analyze_plan(cls.plan)

    def test_detects_resource_deletion(self):
        issues = [finding["issue"] for finding in self.findings]

        self.assertIn(
            "Resource deletion detected.",
            issues,
        )

    def test_detects_public_network_access(self):
        issues = [finding["issue"] for finding in self.findings]

        self.assertIn(
            "Resource allows traffic from the public internet.",
            issues,
        )

    def test_detects_disabled_encryption(self):
        issues = [finding["issue"] for finding in self.findings]

        self.assertTrue(
            any("Encryption is disabled" in issue for issue in issues)
        )

    def test_detects_wildcard_iam_permissions(self):
        issues = [finding["issue"] for finding in self.findings]

        self.assertIn(
            "IAM configuration contains wildcard permissions.",
            issues,
        )

    def test_generates_markdown_report(self):
        report = create_report(self.findings)

        self.assertIn("# Terraform Change Guardian Report", report)
        self.assertIn("Total risk score", report)
        self.assertIn("CRITICAL", report)
        self.assertIn("HIGH", report)


if __name__ == "__main__":
    unittest.main()
