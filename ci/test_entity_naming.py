"""Assert-based self-check: python3 ci/test_entity_naming.py."""

import json
import subprocess
import tempfile
from pathlib import Path

from check_entity_naming import ENTITY, check_repo

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    valid = {
        "LICENSE.txt": (
            f"Copyright 2026 {ENTITY}\n\nApache License\n"
            "Copyright [yyyy] [name of copyright owner]\n"
        ),
        "NOTICE.txt": (
            f"Copyright 2026 {ENTITY}\n\n====================\n"
            "Copyright Identity Digital\n"
        ),
        "CLI_BINARY_LICENSE": f"Copyright 2026 {ENTITY}\n\nApache License\n",
        "SECURITY.md": f"{ENTITY} takes security seriously.\nhttps://github.com/Identity-Digital/dnsid\n",
        "package.json": json.dumps({"author": ENTITY}),
        "pyproject.toml": (
            f'[project]\nname = "example"\nauthors = [{{name = "{ENTITY}"}}]\n'
        ),
        "README.md": "Identity Digital is the parent brand.\n<ENTITY> is an example.\n",
        "version.py": f'ABOUT = "{ENTITY}"\n',
        "go.mod": "module github.com/dnsid-ai/dnsid-go\n",
        "doc.go": f"// Copyright 2026 {ENTITY}\npackage dnsid\n",
    }
    for name, content in valid.items():
        (root / name).write_text(content)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    assert not check_repo(root), check_repo(root)
    example = root / "examples" / "demo"
    example.mkdir(parents=True)
    (example / "go.mod").write_text(
        "module github.com/dnsid-ai/dnsid-go/examples/demo\n"
    )
    aws = root / "key" / "aws"
    aws.mkdir(parents=True)
    for name in ("LICENSE.txt", "NOTICE.txt", "doc.go"):
        (aws / name).write_text(valid[name])
    (aws / "go.mod").write_text("module github.com/dnsid-ai/dnsid-go/key/aws\n")
    cli = root / "cmd"
    cli.mkdir()
    cli_source = (
        'package main\nimport "github.com/identity-digital/dnsid/example"\n'
        f'var about = "{ENTITY}"\n'
    )
    (cli / "main.go").write_text(cli_source)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    assert not check_repo(root), check_repo(root)

    invalid = [
        ("CLI_BINARY_LICENSE", "Copyright 2026 <ENTITY>\n\nApache License\n"),
        ("LICENSE.txt", "Copyright 2026 Identity Digital\n\nApache License\n"),
        ("NOTICE.txt", "Copyright 2026 <ENTITY>\n"),
        ("NOTICE.txt", (
            f"Copyright 2026 {ENTITY}\n\n"
            "Provided by [Known Systems AI, Inc. (company name)].\n"
        )),
        ("SECURITY.md", f"{ENTITY}\nIdentity Digital takes security seriously.\n"),
        ("SECURITY.md", f"{ENTITY}\nKnown Systems' commercial products.\n"),
        ("SECURITY.md", f"{ENTITY}\nContact [COMPANY NAME].\n"),
        ("package.json", "{}"),
        ("package.json", json.dumps({"author": "Identity Digital"})),
        ("pyproject.toml", '[project]\nname = "example"\n'),
        ("pyproject.toml", '[project]\nauthors = [{name = "<ENTITY>"}]\n'),
        ("version.py", 'ABOUT = "Identity Digital"\n'),
        ("doc.go", "// Copyright 2026 Identity Digital\npackage dnsid\n"),
    ]
    for name, content in invalid:
        (root / name).write_text(content)
        assert check_repo(root), (name, content)
        (root / name).write_text(valid[name])

    (cli / "main.go").write_text('package main\nvar about = "Identity Digital"\n')
    assert check_repo(root), "CLI about text must name the company"
    (cli / "main.go").write_text(cli_source)

    (aws / "NOTICE.txt").write_text(f"Copyright 2026 {ENTITY}\n")
    assert check_repo(root), "module notices must match the complete root copy"
    (aws / "NOTICE.txt").write_text(valid["NOTICE.txt"])

    (root / "package.json").write_text(json.dumps({"author": {"name": ENTITY}}))
    assert not check_repo(root), check_repo(root)
    (root / "LICENSE.txt").unlink()
    try:
        check_repo(root)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("a missing tracked license must fail closed")

print("Entity-naming self-check passed.")
