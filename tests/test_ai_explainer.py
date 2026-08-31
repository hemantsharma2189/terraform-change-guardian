import unittest

from ai_explainer import build_prompt


class TestAIExplainer(unittest.TestCase):

    def test_prompt_contains_security_report(self):
        risk_report = """
        HIGH: aws_security_group.public_web
        Resource allows traffic from the public internet.
        """

        prompt = build_prompt(risk_report)

        self.assertIn(
            "aws_security_group.public_web",
            prompt,
        )
        self.assertIn(
            "Resource allows traffic from the public internet.",
            prompt,
        )

    def test_prompt_requests_required_analysis(self):
        prompt = build_prompt("Example Terraform finding")

        self.assertIn("technical risk", prompt)
        self.assertIn("business impact", prompt)
        self.assertIn("practical remediation", prompt)
        self.assertIn("confidence level", prompt)

    def test_prompt_prevents_unsupported_claims(self):
        prompt = build_prompt("Example Terraform finding")

        self.assertIn(
            "Do not invent evidence",
            prompt,
        )


if __name__ == "__main__":
    unittest.main()
