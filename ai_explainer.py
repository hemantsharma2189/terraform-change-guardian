import argparse
import json
import os
from pathlib import Path
from urllib import request, error


def build_prompt(risk_report):
    return f"""
You are a cloud security and DevSecOps assistant.

Analyze the Terraform security report below.

For every finding:
1. Explain the technical risk.
2. Describe the possible business impact.
3. Recommend a practical remediation.
4. Provide a confidence level.
5. Do not invent evidence that is not present in the report.

Terraform security report:

{risk_report}
"""


def request_ai_analysis(prompt):
    api_url = os.getenv(
        "AI_API_URL",
        "https://api.openai.com/v1/chat/completions",
    )
    api_key = os.getenv("AI_API_KEY")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")

    if not api_key:
        raise RuntimeError(
            "AI_API_KEY is not configured. "
            "Add it as an environment variable or GitHub Actions secret."
        )

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You provide evidence-based Terraform security analysis "
                    "and safe remediation guidance."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
    }

    api_request = request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(api_request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8")
        raise RuntimeError(
            f"AI API request failed with status {exc.code}: {response_body}"
        ) from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach AI API: {exc.reason}") from exc

    try:
        return result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(
            "AI API returned an unexpected response format."
        ) from exc


def main():
    parser = argparse.ArgumentParser(
        description="Generate AI-assisted remediation guidance."
    )
    parser.add_argument(
        "report",
        help="Path to the Terraform risk report",
    )
    parser.add_argument(
        "--output",
        default="ai-remediation.md",
        help="Output path for AI-generated guidance",
    )
    args = parser.parse_args()

    report_path = Path(args.report)

    if not report_path.exists():
        raise SystemExit(f"Risk report not found: {report_path}")

    risk_report = report_path.read_text(encoding="utf-8")
    prompt = build_prompt(risk_report)
    analysis = request_ai_analysis(prompt)

    output = "\n".join(
        [
            "# AI-Assisted Terraform Remediation Report",
            "",
            analysis,
            "",
            "> AI-generated recommendations require human review before deployment.",
        ]
    )

    Path(args.output).write_text(output, encoding="utf-8")
    print(output)
    print(f"\nAI remediation report saved to {args.output}")


if __name__ == "__main__":
    main()
