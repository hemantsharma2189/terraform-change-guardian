import argparse
import json
from pathlib import Path


SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}


def add_finding(findings, severity, resource, issue, recommendation):
    findings.append(
        {
            "severity": severity,
            "score": SEVERITY_SCORE[severity],
            "resource": resource,
            "issue": issue,
            "recommendation": recommendation,
        }
    )


def contains_public_cidr(value):
    if isinstance(value, dict):
        return any(contains_public_cidr(item) for item in value.values())

    if isinstance(value, list):
        return any(contains_public_cidr(item) for item in value)

    return value in ["0.0.0.0/0", "::/0"]


def contains_wildcard(value):
    if isinstance(value, dict):
        return any(contains_wildcard(item) for item in value.values())

    if isinstance(value, list):
        return any(contains_wildcard(item) for item in value)

    return value == "*"


def analyze_plan(plan):
    findings = []

    for change in plan.get("resource_changes", []):
        address = change.get("address", "unknown-resource")
        resource_type = change.get("type", "unknown")
        actions = change.get("change", {}).get("actions", [])
        after = change.get("change", {}).get("after") or {}

        if "delete" in actions and "create" in actions:
            add_finding(
                findings,
                "HIGH",
                address,
                "Resource replacement detected.",
                "Review downtime and data-loss risk before approval.",
            )
        elif "delete" in actions:
            add_finding(
                findings,
                "CRITICAL",
                address,
                "Resource deletion detected.",
                "Confirm the deletion is intentional and ensure backups exist.",
            )

        if contains_public_cidr(after):
            add_finding(
                findings,
                "HIGH",
                address,
                "Resource allows traffic from the public internet.",
                "Restrict CIDR ranges and apply least-privilege network access.",
            )

        if resource_type in ["aws_iam_policy", "aws_iam_role_policy"]:
            if contains_wildcard(after):
                add_finding(
                    findings,
                    "HIGH",
                    address,
                    "IAM configuration contains wildcard permissions.",
                    "Replace wildcard permissions with specific actions and resources.",
                )

        encryption_fields = [
            "encrypted",
            "server_side_encryption",
            "storage_encrypted",
        ]

        for field in encryption_fields:
            if field in after and after[field] is False:
                add_finding(
                    findings,
                    "HIGH",
                    address,
                    f"Encryption is disabled in '{field}'.",
                    "Enable encryption using an approved KMS key.",
                )

        if resource_type.startswith("aws_"):
            tags = after.get("tags") or after.get("tags_all") or {}

            if not tags:
                add_finding(
                    findings,
                    "LOW",
                    address,
                    "AWS resource does not contain tags.",
                    "Add owner, environment, project, and cost-center tags.",
                )

    return findings


def create_report(findings):
    total_score = sum(item["score"] for item in findings)

    lines = [
        "# Terraform Change Guardian Report",
        "",
        f"**Total findings:** {len(findings)}",
        f"**Total risk score:** {total_score}",
        "",
    ]

    if not findings:
        lines.append("✅ No configured infrastructure risks were detected.")
        return "\n".join(lines)

    findings.sort(key=lambda item: item["score"], reverse=True)

    for finding in findings:
        lines.extend(
            [
                f"## {finding['severity']}: {finding['resource']}",
                "",
                f"**Issue:** {finding['issue']}",
                "",
                f"**Recommendation:** {finding['recommendation']}",
                "",
            ]
        )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Terraform JSON plans for security and operational risks."
    )
    parser.add_argument("plan", help="Path to Terraform plan JSON file")
    parser.add_argument(
        "--output",
        default="risk-report.md",
        help="Markdown report output path",
    )
    args = parser.parse_args()

    plan_path = Path(args.plan)

    if not plan_path.exists():
        raise SystemExit(f"Plan file not found: {plan_path}")

    with plan_path.open("r", encoding="utf-8") as file:
        plan = json.load(file)

    findings = analyze_plan(plan)
    report = create_report(findings)

    Path(args.output).write_text(report, encoding="utf-8")

    print(report)
    print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
