# RFC 9421 HTTP Message Signatures Profile

## Draft 01 key role

For `dnsid-draft-01` and verification-only `DNSid1`, application signatures use
the verified agent `ku` key. `ek` is only for the DNSid identity record and
accountable-entity lifecycle signatures.

HTTP Message Signatures are an application profile. They are not part of the
DNSid protocol core.

## Standards and scope

- RFC 9421: HTTP Message Signatures
- RFC 9530: Content-Digest and Repr-Digest
- RFC 8941: Structured Field Values for HTTP
- RFC 9110: HTTP Semantics

An RFC 9651 parser MAY be used, but `Signature-Input`, `Signature`, component
identifiers, and profile parameters MUST remain in the RFC 8941 data model.
RFC 9651-only Date and Display String values MUST be rejected.

The first public SDK profile is deliberately a constrained RFC 9421 profile.
It does not claim complete support for every RFC 9421 component parameter.
Unsupported syntax MUST be rejected rather than accepted with ignored
semantics.

The profile depends only on the shared `IdentityResolver` contract in
[README.md](README.md#shared-profile-contracts),
[`KeyProvider`](01-core-identity-manager.md#keyprovider-interface), and verified
[`VerifiedDomain`](07-protocol-data-types.md#verifieddomain) key material.

## Configuration

| Field | Type | Default | Requirement |
|---|---|---:|---|
| `httpMessageSignatures.maxAge` | seconds | 300 | Positive upper bound for `now - created` and `expires - created`. |
| `httpMessageSignatures.clockSkew` | seconds | 5 | Non-negative tolerance for future `created` and elapsed `expires`. |

Configuration outside these bounds is an argument error. Applications needing
strict replay prevention also maintain a nonce store for at least `maxAge +
clockSkew`; the SDK does not maintain one by default.

## Structured Field data model

### `ComponentIdentifier`

A component identifier contains:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | A supported derived component or lowercase HTTP field name. |
| `parameters` | ordered list of `(name, RFC 8941 bare item)` | no | Parameters in serialization order. |

Bindings MAY accept a map for newly constructed values if their language
preserves insertion order. Parsers MUST retain parameter order. Equality and
duplicate detection compare the component name and parameter values without
regard to parameter order. Two identifiers that differ only by `;req` versus
`;req=?1` are equal because both parse to Boolean true.

The supported component forms are:

| Component | Allowed parameters | Requirements |
|---|---|---|
| `@method`, `@authority`, `@target-uri`, `@path`, `@query`, `@request-target`, `@scheme` | none, or `req` in a response signature | Derived exactly as specified by RFC 9421 §2.2. |
| `@query-param` | required string `name`; optional `req` in a response signature | Apply RFC 9421 §2.2.8 form decoding and canonical re-encoding. Reject absent or repeated selected query parameters. |
| `@status` | none | Response signatures only. |
| lowercase HTTP field name | none; `key`; or `req` combined with either form in a response signature | `key` selects one member after parsing the field as an RFC 8941 Dictionary. |

For this release:

- `req` MUST have the value Boolean true and MUST be used only while signing or
  verifying a response with its originating request available.
- `key` MUST be a non-empty string and MUST be used only on a field component.
  Its RFC 9421 Structured Field semantics apply without also emitting `sf`.
- `name` MUST be a non-empty string and is valid only on `@query-param`.
- Explicit `sf`, `bs`, and `tr` component parameters are unsupported.
- Unknown parameters, wrong types, wrong applicability, unavailable request
  context, and unsupported combinations are errors.
- Duplicate equivalent component identifiers are errors.

This is the complete supported matrix. Adding another parameter requires a
design change and shared conformance vectors before an SDK accepts it.

### `SignatureParams`

One `Signature-Input` member contains:

| Field | Type | Description |
|---|---|---|
| `label` | RFC 8941 dictionary key | Label shared with the corresponding `Signature` member. |
| `components` | ordered component list | Covered components in signature-base order. |
| `parameters` | ordered RFC 8941 parameter list | Every signature parameter, including unknown registered extensions. |

Bindings MAY expose typed accessors for `keyid`, `alg`, `created`, `expires`,
`nonce`, and `tag`, but the ordered parameter list is the serialization source
of truth. Known parameter names MUST NOT occur more than once and have these
types:

| Parameter | Type |
|---|---|
| `keyid`, `alg`, `nonce`, `tag` | String |
| `created`, `expires` | Integer |

Unknown RFC 8941-compatible signature parameters are retained as parsed bare
items in their original parameter order. Unknown signature parameters are not
the same as unknown component parameters: the former are preserved; the latter
are rejected because their extraction semantics are unknown.

There is no `rawSignatureInputMember`. RFC 9421 verification parses the selected
Inner List and serializes that data model according to RFC 8941. It preserves
list and parameter order but canonicalizes equivalent wire spellings and
whitespace. For example, a received `;extension=?1` serializes as
`;extension` in `@signature-params`.

## Parsing and serialization

`ParseSignatureInput` MUST parse the complete field as an RFC 8941 Dictionary
of Inner Lists. It rejects malformed members, duplicate labels, invalid
component identifiers, duplicate equivalent components, duplicate known
signature parameters, and invalid parameter types.

`ParseSignature` MUST parse the complete field as an RFC 8941 Dictionary whose
members are byte sequences. It rejects duplicate labels and every other member
type.

`SerializeComponentIdentifier` and signature-parameter serialization MUST use
RFC 8941 serialization. Implementations MUST NOT:

- split Structured Fields with ad hoc comma, semicolon, or equals parsing;
- reuse an arbitrary raw header substring in the signature base;
- discard unknown valid signature parameters;
- accept a component parameter without implementing its extraction semantics.

A verifier considers labels present in both dictionaries. A profile-specific
`tag` selector first limits candidates to that tag. It validates each candidate
against the profile and accepts only when exactly one candidate verifies.
Well-formed unrelated or verification-invalid coexisting signatures do not
invalidate that candidate; zero valid candidates and multiple valid candidates
are errors. A malformed Structured Field still makes the complete field
unparseable.

## Signature-base construction

`BuildSignatureInput(message, params)` implements RFC 9421 §2.5:

1. Validate every component and reject duplicates.
2. Resolve each component from the correct request or response context.
3. Serialize the component identifier canonically and append
   `identifier + ": " + value`.
4. Canonically serialize the parsed component list and ordered signature
   parameters for the final `"@signature-params"` line.
5. Join lines with a single LF and encode as UTF-8.

Field values, repeated field-line combination, derived components, and request
context MUST follow RFC 9421 and RFC 9110. Implementations must use a message
abstraction that retains the information those rules require. In particular,
proxy deployments MUST establish trusted scheme and authority before
verification; untrusted forwarding headers do not define `@authority` or
`@target-uri`.

The shared `@query-param` vector covers reserved-character decoding and
re-encoding. It does not currently cover `+` versus `%20`, empty, absent, or
duplicate values; their handling is still required by RFC 9421 §2.2.8 and the
supported component rules above. For example `?a!=v!` produces:

```text
"@query-param";name="a%21": v%21
```

For `key`, the selected dictionary member is serialized according to RFC 8941.
Malformed dictionaries and absent members are errors.

`SignHttpMessage` adds or replaces only the selected label in `Signature-Input`
and `Signature`; other valid dictionary members are preserved through parse
and serialization. Callers set ordinary fields such as `Content-Digest` and
`Signature-Agent` before signing.

## Content-Digest

The DNSid HTTP-signature profile requires a covered SHA-256 `Content-Digest`
when HTTP content is supplied, including a supplied zero-length content stream.
A message with no content and no digest does not require one.

The digest input is the HTTP content available at the signing/verifying layer
after transfer framing is removed and before an application or middleware
changes content coding or representation bytes. Implementations MUST NOT infer
content presence solely from `Content-Length` or transfer encoding.

Signing and verification either buffer and restore the exact content bytes or
use a language-native replay mechanism. A one-shot stream without such a
mechanism is rejected. When `content-digest` is covered, verification:

1. Requires and parses `Content-Digest` as an RFC 9530 dictionary.
2. Selects the supported `sha-256` member.
3. Reads the exact content bytes, including an empty byte sequence.
4. Compares the recomputed digest in constant time.
5. Restores the stream before dispatching the request.

A covered digest is always checked. A signed digest value alone does not prove
that it matches the content.

## DNSid request profile

### Signing

`CreateSignedHttpRequest` and `CreateSignedHttpClient` cover exactly these
minimum components:

- `@method`
- `@authority`
- `@target-uri`
- `content-digest` when content is supplied

Additional components must satisfy the supported matrix above. Required
components use exact identifiers, not name-only matching.

The signature parameters are:

- label `sig1` by default;
- `keyid="{domain}#{kid}"` using the shared compound key ID;
- a mapped `alg`;
- integer `created`;
- a cryptographically random base64url nonce.

A signing key `kid` containing `#` is invalid.

### Verification

`VerifySignedHttpRequest` performs these checks before accepting the request:

1. Parse both complete Structured Field dictionaries and identify complete
   candidates. Ignore well-formed unrelated or verification-invalid coexisting
   signatures, but require exactly one candidate to satisfy the DNSid profile
   and verify successfully.
2. Require exact unparameterized `@method`, `@authority`, and `@target-uri`.
3. Parse the compound `keyid`, verify the domain with the current invocation's
   trusted application peer certificate when supplied, and select the verified
   `ku` key by `kid`. Missing peer evidence fails if `fl=mtls`; cached identity
   evidence cannot substitute for the current peer.
4. Require integer `created`; reject `created > now + clockSkew` and
   `now - created > maxAge`.
5. When `expires` is present, require `created <= expires`, reject
   `expires - created > maxAge`, and reject `now > expires + clockSkew`.
6. Apply the content rules above.
7. Resolve the verification algorithm. Application policy, JWK metadata, and
   `alg`, when present, MUST agree. No source is more authoritative than the
   others.
8. Canonically rebuild the RFC 9421 signature base and verify the signature.

Freshness limits replay exposure but do not detect reuse. Applications needing
one-time requests store and reject repeated `(keyid, nonce)` values.

### Algorithm mapping

| JWK/JOSE `alg` | HTTP Message Signature `alg` |
|---|---|
| `EdDSA` | `ed25519` |
| `ES256` | `ecdsa-p256-sha256` |

Other algorithms are rejected. Draft 01 `ku` keys require their JWK algorithm
binding to agree with the selected algorithm.

## Resource limits

The SDK or its documented hosting-layer preconditions MUST impose finite limits
on signature header bytes, candidate labels, covered components, and buffered
content. Enforce limits before expensive parsing/domain lookups or while reading
content, not after unbounded allocation. Exceeding a limit rejects verification;
never inspect only the first N candidates and claim exactly one verifies.
Document the enforcing layer and bounds; standalone helpers need safe limits
when the host supplies none. Body replay MUST preserve the exact bytes within
that bound. The overall verification budget in the
[shared contracts](README.md#verification-resource-budgets) includes every
candidate's domain verification and digest work.

## Shared conformance vectors

[`conformance/http-message-signatures.json`](conformance/http-message-signatures.json)
is normative for SDK behavior in this profile. It tests signature-base
construction and fail-closed component validation without depending on one
SDK's signing implementation. Exact error text is not normative.
