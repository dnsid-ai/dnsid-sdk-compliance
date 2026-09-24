"""Run with python ci/test_workflow_credentials.py (requires PyYAML)."""
from pathlib import Path

import yaml

workflows = Path(__file__).resolve().parents[1] / ".github/workflows"
for path in workflows.glob("*.y*ml"):
    text = path.read_text()
    assert "GH_PAT" not in text, path
    for job in yaml.safe_load(text).get("jobs", {}).values():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, (path, step)
            if "ci/run-one.sh" in step.get("run", ""):
                assert "GH_TOKEN" not in step.get("env", {}), (path, step)
compliance = yaml.safe_load((workflows / "sdk-compliance.yaml").read_text())
assert compliance["jobs"]["compliance"]["permissions"] == {"contents": "read"}
assert compliance["jobs"]["comment"]["permissions"] == {"issues": "write"}
assert compliance["jobs"]["comment"]["needs"] == "compliance"
assert "always()" in compliance["jobs"]["comment"]["if"]
assert all("GH_TOKEN" not in step.get("env", {}) for step in compliance["jobs"]["compliance"]["steps"])
assert all(
    "run-one.sh" not in step.get("run", "") and not step.get("uses", "").startswith("actions/checkout@")
    for step in compliance["jobs"]["comment"]["steps"]
)
assert not (workflows / "sdk-release-readiness.yaml").exists()
assert "secrets: inherit" not in (workflows / "smoke-test.yml").read_text()
