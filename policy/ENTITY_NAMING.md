# Entity naming

**Known Systems AI, Inc.** is the legal and copyright entity for DNSid. Use that
exact name in first-party LICENSE/CLI_BINARY_LICENSE and NOTICE attribution,
copyright headers, security and other legal policies, package author metadata,
Go module documentation, and CLI version/about/help text that names the company.
Identity Digital, Identity Digital Innovation Labs (IDIL), Identity-Digital, and
dnsid-ai identify parent/lab brands or GitHub organizations, not the legal entity.
Keep those names in valid product prose, repository/module URLs, and image paths.
Do not ship unresolved company-name placeholders.

## Applying the rule

- Add first-party attribution before standard license text. Do not rewrite
  standard license terms or their instructional examples, such as
  `Copyright [yyyy] [name of copyright owner]`.
- Preserve third-party copyright notices and license text. In NOTICE files,
  keep first-party attribution before the separator that starts dependency notices.
- Set npm `author` (a string or an object with `name`) and Python
  `project.authors` to the legal entity. This includes recipe and example manifests.
- Include LICENSE and NOTICE attribution in distributed packages and independently
  versioned Go modules. Keep the Go AWS module's legal files synchronized with
  the root copies.
- The TypeScript workspace `prepack` hooks copy the canonical root NOTICE into
  each public package. Generated workspace notices are ignored by Git.
- SDK and cookbook contribution guides link here rather than copy this rule.

## Checking

Python 3.11+ and Git are sufficient:

```sh
python3 ci/test_entity_naming.py
python3 ci/check_entity_naming.py /path/to/repo [/path/to/another-repo ...]
make entity-naming  # this repo and the four sibling checkouts
```

The checker reads tracked files. Stage new authoritative files before running it
locally. It checks first-party license/notice attribution, security and named
legal policies, author metadata, Go SDK module documentation, copyright headers,
and static CLI/about/version source text. It excludes dependencies, test
fixtures, standard license examples, and dependency notices after their separator.
It does not ban brand names from ordinary documentation or change third-party
attribution. Runtime-composed CLI legal strings still need review when added.

The cross-SDK CI workflow checks all five repositories on pull requests, pushes
to main, manual dispatch, and its daily schedule. The reusable SDK workflow also
checks each SDK PR head directly, outside the protocol regression-only gate.
Naming errors always fail; they are not known bugs or protocol exceptions.

When introducing this rule, merge the SDK and cookbook attribution changes
before requiring the new central check to pass against their main branches.
