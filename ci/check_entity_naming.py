"""Check first-party legal attribution in one or more Git checkouts (Python 3.11+)."""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ENTITY = "Known Systems AI, Inc."
WRONG_ENTITY = re.compile(
    r"\b(?:Identity[ -]Digital(?: Innovation Labs)?|IDIL)\b"
    r"|Known Systems(?! AI, Inc\.)",
    re.IGNORECASE,
)
WRONG_ATTRIBUTION = re.compile(
    r"(?:\bcopyright\b\s*(?:\(c\)|©)?\s*(?:\d{4}(?:[-–]\d{4})?\s*)?"
    r"|\b(?:licensor|(?:legal|contracting)[ _-]*entity|company(?:[ _-]*name)?"
    r"|copyright[ _-]*(?:owner|holder|entity))\b\s*(?:(?:is|:|=)\s*)?[\"'`]?"
    r"|\b(?:licensed|operated|provided|owned) by\s+"
    r"|\bbetween\b[^\n]{0,80}\band\s+)"
    rf"(?:{WRONG_ENTITY.pattern})"
    rf"|(?:{WRONG_ENTITY.pattern})(?:\s+takes\b[^\n]{{0,80}}\bsecurity\b"
    r"|\s+terms of (?:use|service)\b|['’]s?\s+commercial (?:products|services)\b)",
    re.IGNORECASE,
)
STANDARD_LICENSE_EXAMPLE = re.compile(
    r"(?im)^[ \t]*Copyright (?:\[yyyy\] \[name of copyright owner\]"
    r"|\{yyyy\} \{name of copyright owner\})[ \t]*$",
)
PLACEHOLDER = re.compile(
    r"[<\[{]\s*(?:Known Systems AI, Inc\.[^\]>}\n]*"
    r"|(?:your\s+)?(?:entity|company|legal entity|entity name|company name|legal name)"
    r"|name of copyright owner|copyright owner)\s*[>\]}]",
    re.IGNORECASE,
)
EXCLUDED = {
    "node_modules", "vendor", "third_party", "third-party", ".venv", "dist", "build",
    "fixtures", "testdata", "tests", "test",
}
POLICIES = {"SECURITY.md", "CODE_OF_CONDUCT.md", "PRIVACY.md", "TERMS.md"}
SOURCE_SUFFIXES = {".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".sh"}


def naming_errors(text: str, *, attribution: bool = True) -> list[str]:
    """Check attribution, not unrelated parent-brand or product explanations."""
    prose = re.sub(
        r"https?://\S+|(?:Identity-Digital|dnsid-ai)/[\w./#-]+",
        "", text, flags=re.IGNORECASE,
    )
    errors = []
    wrong_name = WRONG_ENTITY if attribution else WRONG_ATTRIBUTION
    if wrong_name.search(prose):
        errors.append(f"use {ENTITY}, not a brand or abbreviated company name")
    if PLACEHOLDER.search(prose):
        errors.append("unresolved entity-name placeholder")
    return errors


def check_repo(root: Path) -> list[str]:
    """Read tracked first-party files, excluding dependencies and test fixtures."""
    paths = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z"], text=True
    ).split("\0")
    files = {Path(name) for name in paths if name}
    errors = []

    def fail(path: Path, message: str) -> None:
        errors.append(f"{root / path}: {message}")

    for alternatives in (
        ("LICENSE", "LICENSE.txt"), ("NOTICE", "NOTICE.txt"), ("SECURITY.md",)
    ):
        if not any(Path(name) in files for name in alternatives):
            fail(Path(alternatives[0]), "required authoritative file is missing")

    for path in sorted(files):
        if (
            EXCLUDED.intersection(path.parts)
            or path.name.startswith("test_")
            or "test." in path.name
        ):
            continue
        legal = (
            path.name.startswith(("LICENSE", "NOTICE"))
            or path.name == "CLI_BINARY_LICENSE"
        )
        source = path.suffix in SOURCE_SUFFIXES and not path.name.endswith("_test.go")
        policy = path.name in POLICIES or (
            path.stem.lower() in {"terms", "privacy", "legal"}
            and path.suffix in SOURCE_SUFFIXES | {".md", ".txt", ".html"}
        )
        metadata = path.name in {"package.json", "pyproject.toml"}
        if not (legal or policy or metadata or source):
            continue
        text = (root / path).read_text(encoding="utf-8")
        if metadata:
            if path.name == "package.json":
                author = json.loads(text).get("author")
                name = author.get("name") if isinstance(author, dict) else author
                if name != ENTITY:
                    fail(path, f"author must name {ENTITY}")
            else:
                project = tomllib.loads(text).get("project")
                if project is not None:
                    authors = project.get("authors", [])
                    if not any(author.get("name") == ENTITY for author in authors):
                        fail(path, f"project.authors must name {ENTITY}")
                    for author in authors:
                        for message in naming_errors(author.get("name", "")):
                            fail(path, message)
        elif legal or policy:
            own_text = text
            if path.name.startswith("NOTICE"):
                # Dependency attribution starts at the first notice separator.
                own_text = re.split(r"\n={10,}", text, maxsplit=1)[0]
            elif legal:
                # Ignore the instructional example, not the rest of the license.
                own_text = STANDARD_LICENSE_EXAMPLE.sub("", text)
            if (legal or path.name == "SECURITY.md") and ENTITY not in own_text:
                fail(path, f"first-party attribution must name {ENTITY}")
            for message in naming_errors(own_text, attribution=False):
                fail(path, message)
        else:
            # shortcut: static CLI text only; review runtime-composed legal strings.
            about_file = (
                any(part in {"cmd", "cli"} for part in path.parts)
                or re.search(
                    r"(?:^|[-_])(about|version|cli)(?:[-_.]|$)",
                    path.name, re.IGNORECASE,
                )
            )
            for number, line in enumerate(text.splitlines(), 1):
                if "copyright" in line.lower() or about_file:
                    for message in naming_errors(line):
                        fail(path, f"line {number}: {message}")

    for path in files:
        if path.name == "go.mod" and re.match(
            r"module github.com/dnsid-ai/dnsid-go(?:/key/aws)?\s",
            (root / path).read_text(),
        ):
            doc = path.with_name("doc.go")
            if doc not in files or ENTITY not in (root / doc).read_text():
                fail(doc, f"module documentation must name {ENTITY}")
            for name in ("LICENSE.txt", "NOTICE.txt"):
                attribution = path.with_name(name)
                if attribution not in files:
                    fail(attribution, "module attribution is missing")
                elif path.parent != Path(".") and (
                    (root / attribution).read_bytes() != (root / name).read_bytes()
                ):
                    fail(attribution, "module attribution differs from the root copy")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repos", nargs="+", type=Path)
    args = parser.parse_args()
    errors = []
    for root in args.repos:
        try:
            errors.extend(check_repo(root))
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            errors.append(f"{root}: cannot check entity naming: {exc}")
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print(f"Entity naming passed for {len(args.repos)} repositories.")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
