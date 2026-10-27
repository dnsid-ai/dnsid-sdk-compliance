# RFC 9421 HTTP Message Signatures Profile

## Draft 01 key role

For `dnsid-draft-01` and verification-only `DNSid1`, application signatures use
the verified agent `ku` key. `ek` is only for the DNSid identity record and
accountable-entity lifecycle signatures.

HTTP Message Signatures are an application profile. They are not part of the
DNSid protocol core.

## Standards and scope

- RFC 9421: HTTP Message Signatures, including §5 signature requests
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

Both settings MUST be finite numeric values, not Booleans. Defaults apply only
when omitted; explicit zero clock skew means zero tolerance. Configuration
outside these bounds is an `ArgumentError`, rejected before network work.
Apply shared [profile configuration ownership](README.md#profile-configuration-ownership).
Applications needing strict replay prevention also maintain a nonce store for at least `maxAge +
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
unparseable. Negotiated response verification first selects the locally requested
label, so unrelated complete signatures cannot satisfy or make that selection
ambiguous. The WBA profile explicitly overrides this selection rule with
exactly-one-complete-candidate selection for requests and per-key directory
signatures; see [10: Signature selection](10-web-bot-auth.md#signature-selection).

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
abstraction that retains the information those rules require, including the
actual response status for `@status` and the originating request for `req`.
In particular, proxy deployments MUST establish trusted scheme and authority before
verification; untrusted forwarding headers do not define `@authority` or
`@target-uri`.

Shared `@query-param` vectors cover reserved characters, `+` versus `%20`, and
empty values. Form-percent encoding preserves `*` but encodes `~` as `%7E` and
spaces as `%20`; RFC 3986's unreserved-character set is not a substitute.
Absent or duplicate selected parameters still reject. For example `?a!=v!` produces:

```text
"@query-param";name="a%21": v%21
```

For `key`, the selected dictionary member is serialized according to RFC 8941.
Malformed dictionaries and absent members are errors.

`SignHttpMessage` adds or replaces only the selected label in `Signature-Input`
and `Signature`; other valid dictionary members are preserved through parse
and serialization. Callers set ordinary fields such as `Content-Digest` and
`Signature-Agent` before signing. Metadata and signature MUST refer to the same
key: activation between key selection and signing must produce valid matching-key
output or an explicit error, never a silently invalid signature.

## Content-Digest

The DNSid HTTP-signature profile requires a covered SHA-256 `Content-Digest`
when HTTP content is supplied, including a supplied zero-length content stream.
A message with no content and no digest does not require one.

The digest input is the HTTP content available at the signing/verifying layer
after transfer framing is removed and before an application or middleware
changes content coding or representation bytes. Implementations MUST NOT infer
content presence solely from `Content-Length` or transfer encoding.

Signing and verification either buffer and restore the exact content bytes or
use a language-native replay mechanism. Replacing a stream MUST preserve its
native cleanup responsibilities so closing the replay stream releases the
original resources. Repeated signing or verification of the same message MUST
NOT retain earlier replay buffers through cleanup wrappers; retain the original
cleanup responsibility, not a chain of replaced streams. A one-shot stream
without such a mechanism is rejected.
When any `content-digest` component is covered, including a parameterized
component such as `content-digest;key="sha-256"`, verification:

1. Requires and parses `Content-Digest` as an RFC 9530 dictionary.
2. Selects the supported `sha-256` member.
3. Reads the exact content bytes, including an empty byte sequence.
4. Compares the recomputed digest in constant time.
5. Restores the stream before dispatching the request.

A covered digest is always checked. If content was not supplied to the verifier,
a covered digest rejects; absent content is not a supplied empty byte sequence.
For the [negotiated response profile](#dnsid-negotiated-response-profile), HTTP
semantics can establish that a response has no content, such as a response to
HEAD or a 204 or 304 response. Its digest is computed over the empty byte
sequence, as specified by RFC 9530. This does not permit treating an unavailable
ordinary response body as empty.
Digest-validation detection is distinct from exact minimum-coverage checks:
parameterized coverage does not substitute for required unparameterized
`content-digest` coverage. A signed digest value alone does not prove that it
matches the content.

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

## DNSid negotiated response profile

### Scope and public surface

Response authentication is opt-in. Signing a request alone does not authenticate
the responder's DNSid identity. RFC 9421 §5 permits requesting a signed response
with `Accept-Signature`, but permits a server to ignore requests outside its
application policy. This SDK profile makes an enabled client's requirement
mandatory locally: a missing or unacceptable response signature fails closed.
It does not change DNSid core, the request-only defaults, or WBA directory rules.

Bindings MUST expose these capabilities through idiomatic public APIs:

```
TYPE ResponseSignatureOptions
  expectedDomain: string
  additionalComponents?: []ComponentIdentifier
END

HttpSigningOptions.responseSignature?: ResponseSignatureOptions

SignRequestedHttpResponse(request, response) -> HttpResponse
VerifySignedHttpResponse(request, response, opts: ResponseSignatureOptions,
                         peerCert?: TLSCertificate) -> VerifiedDomain
```

The methods belong to the HTTP-signature profile, not `IdentityManager`.
`CreateSignedHttpRequest` prepares the negotiation when `responseSignature` is
present. `CreateSignedHttpClient` (or a binding's signed-fetch equivalent) also
verifies the response before returning it. With the option absent, both retain
the existing request-only behavior. A standalone request helper does not send
or verify a response; its caller uses `VerifySignedHttpResponse` afterward.

`expectedDomain` is a required, locally configured DNSid agent FQDN, normalized
with `NormalizeFQDN` before network work. It may differ from the HTTP endpoint
host, for example behind a gateway. Never derive it from received signature
metadata or redirects. It is not sent as a `keyid` constraint: the server selects
its current operational key. Applications requiring accountable-entity approval
also configure the resolver's `trustedEntities`; an expected agent domain does
not replace that policy. As elsewhere, absent entity policy makes no entity
acceptance decision.

### Client request preparation

When enabled, the helper MUST:

1. Reject an existing `Accept-Signature` field with `ArgumentError`, rather than
   replace or merge caller policy. Manual RFC 9421 negotiation remains possible
   through ordinary headers and low-level primitives outside this convenience.
2. Generate a fresh nonce from at least 32 cryptographically random bytes,
   encoded as canonical unpadded base64url. It is a response challenge, separate
   from the outgoing request signature's nonce.
3. Set one `Accept-Signature` dictionary member, labeled `sig1`, starting with
   these required components in this order:
   - `"@status"`
   - `"@method";req`
   - `"@authority";req`
   - `"@target-uri";req`
   - `"accept-signature";req`
   - `"signature-input";req`
   - `"signature";req`
   - `"content-digest"`
   - `"cache-control"`
   Append any `responseSignature.additionalComponents` in caller order, without
   equivalent duplicates. Validate them against the supported response component
   matrix before network work. Use this existing component model to request
   signed application metadata such as `content-type`; a requested field must
   be present on the response or signing fails.
4. Add the request parameters `created` and `expires` as Boolean true flags,
   and `nonce` as the generated string, in that order. RFC 9421 signature
   requests differ from `Signature-Input`: these two time parameters request
   timestamps; they are not timestamp values.
5. Cover exact unparameterized `accept-signature` in the outgoing request
   signature, in addition to the request profile's usual components.

Covering both request signature fields binds the response to the original
request signer and signed content. A challenge alone can be copied into a
different request. Covering only the request's `Signature` field is insufficient;
its signature parameters must also be bound to prevent the signature-value
substitution described in RFC 9421 §7.3.7.

For example, with a disposable example nonce (production nonces MUST be random):

```http
Accept-Signature: sig1=("@status" "@method";req "@authority";req "@target-uri";req "accept-signature";req "signature-input";req "signature";req "content-digest" "cache-control");created;expires;nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

The signed client MUST retain an invocation-local snapshot of its expected
domain, challenge, and actual outgoing request context. Verification uses this
snapshot, not echoed request metadata, mutable caller options, or a later request.
With standalone helpers, the caller must retain an unmodified prepared request
and original policy snapshot for `VerifySignedHttpResponse`; bindings MUST
document that responsibility. Starting a new attempt requires preparation from
the original unsigned request, with a new challenge and signature. Enabled
helpers MUST reject a non-HTTPS target before sending.

### Server response signing

`SignRequestedHttpResponse` is explicitly invoked by server code before headers
or content are sent. If `Accept-Signature` is absent, it returns the response
unchanged and does not require a signing key. Otherwise it MUST:

1. Parse the complete field as an RFC 8941 Dictionary of Inner Lists. Reject
   malformed syntax, duplicate labels or parameters, wrong parameter types,
   and duplicate equivalent components before a parser can overwrite them.
2. Require exactly one member, with any valid label, all exact required components
   above, and only the required `created`, `expires`, and `nonce` parameters.
   Additional components must satisfy the supported response component matrix.
   Preserve the complete component list and order as requested; equivalent true
   spellings of `req` and the two time flags are accepted. Require a canonical
   unpadded base64url nonce decoding to at least 32 bytes. Unsupported component
   syntax, parameters, constraints, and multi-member negotiation reject; they
   MUST NOT be silently ignored or partially fulfilled.
3. Use the actual final response status and the trusted originating request
   context. Compute and set SHA-256 `Content-Digest` over the exact response
   content, including an empty sequence for a known no-content response.
   Add `Cache-Control: no-store` without dropping existing cache directives.
4. Sign using the current local operational key, never the entity key. Use the
   requested label and exact requested component list, the usual compound
   `keyid` and mapped `alg`, integer `created` and `expires` with positive
   lifetime at most the server's `maxAge`, and the exact requested nonce.
   The requested flags become timestamp values in `Signature-Input`.
5. Preserve signatures under other labels. Reject a collision with the requested
   label in either existing signature dictionary instead of replacing it.
   Publish the response changes only after successful validation and signing;
   key changes or signing failures MUST NOT produce an unsigned fallback.

The complete HTTP message must remain available within the resource bounds
below. Apply the existing body replay and signing-key consistency requirements.
Content coding and other covered fields MUST be finalized before signing, and
middleware MUST NOT modify covered bytes afterward. The client needs those same
content bytes before transparent content decoding; incompatible transports reject
rather than verify altered bytes. Support ordinary final responses, including
HTTP errors and redirects; informational responses and protocol/tunnel upgrades
are outside this helper and MUST NOT be reported as authenticated responses.

This helper does not authenticate the caller, authorize an operation, or prove
that application processing succeeded. Server applications still verify signed
requests and authorize actions before dispatch. An opted-in server SHOULD also
apply signing to its application error responses. If it cannot fulfill a request,
it returns a local error to its hosting application; the host may reject the HTTP
request, but MUST NOT claim to have fulfilled response authentication. Malformed
or unsupported peer negotiation is a non-transient verification error, not an
invalid-local-options error. Missing local signing configuration is `ArgumentError`.

### Client response verification

`VerifySignedHttpResponse` MUST perform all of the following before success:

1. Validate the saved request negotiation and local expected-domain policy,
   including coverage of any locally required additional components. Parse
   the complete response signature dictionaries using the existing rules.
   Require a complete signature under the requested label; an unrelated label
   cannot satisfy the negotiation.
2. Require exactly the requested component list, including order and component
   parameters, and a `nonce` equal to the saved challenge. Reject missing or
   different challenges, even when the signature is otherwise valid. Compare
   parsed identifiers rather than raw wire spellings.
3. Require both integer timestamps and apply the request profile's freshness,
   lifetime, and clock-skew checks, with `created < expires`. Require `alg` and
   the compound `keyid`; its normalized domain MUST equal local `expectedDomain`
   before any DNSid lookup based on received metadata.
4. Call `VerifyDomain(expectedDomain, peerCert)` with the current application
   connection's trusted server certificate when supplied. Enforce status,
   lifecycle binding, freshness, and configured entity acceptance on every
   invocation, including cache hits. Missing current-peer evidence fails when
   `fl=mtls`; a discovery endpoint's certificate is not a substitute.
5. Select the verified current `ku` key by `kid`, enforce algorithm agreement,
   rebuild the signature base using the saved request and actual response, and
   verify the signature. Other well-formed signatures may coexist but cannot
   replace the requested signature.
6. Require covered SHA-256 `Content-Digest`, recompute it over the exact response
   content, and require the signed `Cache-Control` to contain `no-store`.
   Apply the no-content rule above; an unavailable body is not empty content.
   Restore content for the application only after verification succeeds.

Missing signatures, malformed negotiation, unexpected identity, nonce mismatch,
invalid content, and cryptographic failures are non-transient verification
errors. DNSid evidence-acquisition errors retain their existing classification.
Use the binding's existing error mapping; invalid local options are
`ArgumentError`. Never return a successful `VerifiedDomain` or release response
content as authenticated after a failure. Owned response resources MUST be
released on rejection or cancellation.

An enabled signed client MUST retain the native response until verification
succeeds, including for non-2xx responses, and use the invocation's finite budget
for sending, bounded content reads, and verification. It MUST disable automatic
redirect following and request replay/retries in the underlying transport for
this mode. A caller may explicitly start a new attempt, with a fresh challenge
and independently selected expected domain; verification failure never authorizes
an automatic resend of a potentially completed operation. Negotiated responses
MUST NOT be cached or reused across requests. These rules avoid returning a cached
or redirected response that belongs to another challenge or identity.

Only covered fields are authenticated. `Content-Type`, `Content-Encoding`, and
`Location`, for example, are not covered by default. Applications that rely on
such metadata MUST request its coverage through `additionalComponents`, or
supply their own trusted interpretation; they MUST NOT treat uncovered metadata
as signed. Additional coverage does not relax exact requested-list matching.
Response authentication proves possession of the responder's DNSid operational
key when the signed response arrives. HTTPS remains required; this exchange does
not establish entity authentication before sensitive request data is sent, or
provide confidentiality independently of TLS.

### Example flow

```
// Client: the wrapper requests and verifies a signed response before returning.
client = callerProfile.CreateSignedHttpClient(httpsTransport, {
  responseSignature: {expectedDomain: "service.example"}
})
response = client.Send(request)

// Server: existing request verification and application authorization still apply.
caller = serverProfile.VerifySignedHttpRequest(request, peerCert)
response = HandleAuthorizedRequest(caller, request)
response = serverProfile.SignRequestedHttpResponse(request, response)
Send(response)
```

These are conceptual, language-neutral APIs, not claims of released SDK support.
Native coverage requirements are listed in
[conformance](conformance/README.md#negotiated-response-authentication).

## Resource limits

The SDK or its documented hosting-layer preconditions MUST impose finite limits
on signature and `Accept-Signature` header bytes, candidate labels, covered
components, nonce length, and buffered request and response content. Enforce
limits before expensive parsing/domain lookups or while reading content, not
after unbounded allocation. Exceeding a limit rejects verification;
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
