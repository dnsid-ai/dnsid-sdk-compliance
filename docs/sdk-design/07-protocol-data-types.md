# Protocol Data Types

This document defines shared DNSid data structures, wire profiles, and
normalization rules used by core and profile documents.

### Identity Record Behavior Profiles

The `_dnsid` TXT record `v=` tag selects an immutable identity-record behavior
profile. It is not a display version. A profile owns parsing rules, required and
optional known tags, unknown-tag handling, canonicalization, semantic validation,
signature verification key selection, runtime key selection, signature algorithm
policy, serialization rules, and any version-dependent verification behavior.

Parsed records MUST preserve the exact `v=` value found in DNS. Implementations
MUST NOT normalize, rewrite, downgrade, upgrade, or replace that value before
signature verification because `v=` is part of the signed canonical content.
Two selectors may share one behavior implementation, but canonicalization and
serialization always use the exact parsed selector. Unsupported future `v=`
values fail closed with a non-retryable parse error naming the unsupported value.

Submitted drafts use immutable numbered selectors of the form
`dnsid-draft-<nn>`. During the Internet-Draft period, `DNSid1` is the one
specification-defined moving selector: it selects the latest submitted draft
fully supported by that SDK release. When version 1 becomes an RFC, `DNSid1`
freezes permanently to the RFC version 1 behavior. A later standards revision
uses `DNSid2`; the moving-selector rule does not continue after version 1 becomes
an RFC.

Numbered draft profile subsections are frozen except for clarifications that do
not change behavior. Implementations MUST NOT infer ordering or compatibility by
sorting profile identifiers. Support for an unpublished work-in-progress draft
MUST remain off the release branch and MUST NOT appear in a released SDK.

Normal SDK callers do not choose verification behavior profiles manually. Parsers
and verifiers select behavior from the exact `v=` value in DNS. During the draft
period, record builders emit the configured numbered publish profile, initially
`dnsid-draft-01`; they do not publish `DNSid1`. Language bindings may expose
supported selectors and the submitted draft currently selected by `DNSid1` for
diagnostics and conformance tests, but dispatch should remain an internal
protocol concern for ordinary verification.

#### Profile support matrix

| Wire selector | Selected behavior | Parse | Verify | Publish | Status |
| --- | --- | ---: | ---: | ---: | --- |
| `dnsid-draft-01` | submitted `draft-ihsanullah-dnsid-01` | yes | yes | yes | Current numbered draft and default publish profile. |
| `DNSid1` | current submitted Internet-Draft | yes | yes | no | Pre-RFC moving verification selector; currently uses exactly the draft 01 behavior. |

`DefaultPublishProfile = "dnsid-draft-01"`.
`SupportedPublishProfiles = ["dnsid-draft-01"]`.
`SupportedValidationProfiles = ["dnsid-draft-01", "DNSid1"]` for the current
release. A binding MUST NOT advertise a selector unless all required fields,
signature semantics, canonicalization, key-role rules, lifecycle verification
rules, and failure behavior for its selected behavior are implemented.

When a later draft is submitted, a release may add its immutable numbered
profile and advance `DNSid1` to the same behavior. For example, a draft 02
release verifies `dnsid-draft-01` with frozen draft 01 behavior and verifies both
`dnsid-draft-02` and `DNSid1` with draft 02 behavior; it publishes only
`dnsid-draft-02`. SDK and registry releases MUST NOT advance publication until
the submitted numbered profile is fully supported across the release.

A verifier that supports multiple profiles MUST branch on the resolved profile
before required-tag validation, URL host validation, canonicalization, TXT
signature key selection, runtime key selection, key-age checks, lifecycle-log
verification, and JWKS cardinality checks. In particular, implementations MUST
NOT hard-code `ku` as the key for every protocol signature: the draft 01
behavior verifies `sg` with `ek` and runtime/application signatures with `ku`.

The following is the conceptual profile contract used by this design. It is not
a required public API shape; language bindings may implement it with tables,
functions, sealed variants, classes, or other idiomatic mechanisms.

| Operation | Description |
|-----------|-------------|
| `Selectors()` | Returns the exact `v=` selector values that currently use this behavior. Numbered selectors are immutable; pre-RFC `DNSid1` may move only as described below. |
| `RequiredTags()` | Returns the required tag names for parse-time presence and non-empty validation. |
| `OptionalKnownTags()` | Returns optional known tag names that are parsed into the SDK data model. |
| `IsKnownTag(tag)` | Returns whether `tag` is interpreted by this profile rather than preserved only as an unknown extension tag. |
| `ValidateRequiredTags(record)` | Raises `ParseError` if any profile-required tag is missing or empty. |
| `ValidateRequiredNonSignatureTags(record)` | Raises `ParseError` if any profile-required non-signature tag is missing or empty; used while preparing unsigned canonical bytes before `sg` exists. |
| `Canonical(record)` | Builds the signature input for this profile. |
| `Validate(record)` | Performs profile-owned semantic validation that requires identity context, such as URI and FQDN checks. |
| `GovernanceID(record)` | Selects the accountable-entity identifier used for relationship and verifier-local acceptance checks; draft 01 uses `gi`. |
| `HasStructuralGovernanceRelationship(record)` | Returns whether the identity FQDN is equal to or beneath the profile-selected governance domain. A false result is acceptable only when profile-required bilateral lifecycle evidence proves the delegated cross-domain relationship. |
| `SignatureVerificationKeyURI(record)` | Selects the HTTPS JWKS URI used to verify the TXT record's `sg` signature. |
| `SignatureVerificationKeyAllowedHost(record)` | Selects the allowed host for fetching the TXT signature verification JWKS. |
| `SignatureVerificationKeyAllowsDomainBoundary(record)` | Selects whether redirects may stay below the allowed host instead of requiring exact-host redirects. |
| `RuntimeKeyURI(record)` | Selects the HTTPS JWKS URI used for runtime/application signing keys. |
| `RuntimeKeyAllowedHost(record)` | Selects the allowed host for fetching runtime/application signing keys. |
| `KeyAgeSubjectThumbprint(record, recordSigningKey, runtimeJwks)` | Selects the operational key thumbprint to check for `ka` and operation-level log evidence. |
| `SignatureAlgorithmPolicy(record, jwks, parsedSig)` | Defines acceptable TXT signature algorithms and eligible JWKS keys for this profile. |
| `PublishAllowed()` | Returns whether this SDK may create new records for this profile. |
| `BuildUnsignedRecord(config, entityKeyProvider, operationalKeyProvider)` | Builds and validates the profile's publishable unsigned record, preserving the configured exact selector as `v` and enforcing required key-role relationships. |
| `RecordSigningProvider(entityKeyProvider, operationalKeyProvider)` | Selects the provider authorized to sign the TXT record. |
| `EncodeRecordSignature(sig)` | Encodes raw TXT signature bytes in the profile's `sg` wire format. |
| `ValidateVerifiedKeys(recordSigningKey, runtimeJwks)` | Validates profile-owned JWKS cardinality and key-role relationships and returns the selected runtime key. |
| `VerifyLifecycleBinding(record, logReader, recordSigningKey, runtimeKey)` | Performs the profile-required lifecycle binding and continuity checks. |
| `Serialize(record)` | Emits a TXT-record string for this profile. |

`ResolveIdentityRecordProfile(v)` returns a resolved profile while retaining `v`
as its exact wire selector, or no profile if unsupported. A pre-RFC `DNSid1`
resolution may reuse the behavior implementation of the latest supported
submitted numbered draft, but it MUST NOT replace the record's selector before
canonicalization or signature verification.

<a id="profile-dnsid1"></a>

#### Profiles: `dnsid-draft-01` and pre-RFC `DNSid1`

These exact wire selectors use the submitted `draft-ihsanullah-dnsid-01`
behavior. `dnsid-draft-01` is immutable and is the current publish profile.
`DNSid1` is accepted for verification and currently selects the same behavior,
but it is not published while version 1 remains an Internet-Draft. The exact
selector remains part of the signed canonical content.

Required tags: `v`, `gi`, `ek`, `ku`, `lr`, `su`, `sg`.

Optional known tags: `fl`, `ka`, `cu`.

Behavior notes:

- `v` is exactly `dnsid-draft-01` or `DNSid1`. No other spelling or dated
  selector is accepted. Both selectors use these rules without rewriting the
  exact wire value.
- `gi` identifies the accountable entity and MUST be a lowercase ASCII DNS
  domain name. IDNs use lowercase A-label form. URI, DID, VC subject, and other
  external identifiers are reserved for future profiles and MUST NOT be accepted
  in this base profile. For verifier-local acceptance configuration targeting
  this profile, normalize configured `trustedEntities[].governanceId` values with `NormalizeFQDN` and
  reject invalid domains or duplicate normalized identifiers. Compare them
  exactly against `GovernanceID(record)`; do not normalize or rewrite the signed
  record. This policy-input rule does not define normalization for future
  non-domain identifier profiles.
- The agent FQDN MUST be compared with `gi` independently of `ek` host
  validation. Equality or a DNS-label-boundary subdomain relationship is a
  structural self-accounted relationship. An unrelated agent FQDN is a delegated
  cross-domain relationship and is acceptable only when the bilateral ISSUANCE
  event binds that exact agent FQDN to that exact `gi`; without such evidence,
  verification MUST fail closed.
- `ek` is the HTTPS JWKS URI for accountable-entity record-signing keys. Its
  host MUST equal the `gi` domain or be beneath it with DNS-label boundary
  matching. `ek` verifies the `_dnsid` TXT `sg` signature and accountable-entity
  lifecycle-event signatures.
- `ku` is the HTTPS JWKS URI for the DNSid operational/runtime signing key. Its
  host MUST equal the agent FQDN. `ku` is used for runtime/application
  signatures, ISSUANCE countersignatures, and KEY_ROTATION authorizations.
- `ku` MUST NOT be used to verify `sg` under this profile.
- The live `ek` JWKS MUST contain exactly one current accountable-entity
  record-signing key. The live `ku` JWKS MUST contain exactly one current DNSid
  operational signing key. Superseded keys MUST NOT remain on live endpoints;
  historical verification uses public key material recorded in the lifecycle log.
- The current `ek` and current `ku` keys MUST be distinct public keys. Verifiers
  reject identical RFC 7638 JWK thumbprints unless a future profile defines a
  constrained exception.
- `ka` applies only to the operational key discovered through `ku`. Accountable
  entity key-age policy is out of scope for the draft 01 behavior.
- `Canonical()` includes all tags except `sg`, sorted alphabetically by tag name,
  semicolon-separated, with no whitespace, encoded as US-ASCII bytes. `v` does
  not get special first-position treatment in the canonical string.
- `sg` is unpadded base64url of the raw signature bytes. It is not
  algorithm-prefixed. The signature algorithm is determined by the single current
  JWK at `ek`; ES256 support is mandatory and Ed25519 support is recommended.
  ES256 signatures are JWA fixed-width `R || S`, not DER.
- JWK `alg` is REQUIRED on signing keys served by `ek` and `ku` in this profile.
- Verifiers that rely on the DNSid-to-accountable-entity binding MUST verify the
  bilateral ISSUANCE event, including both accountable-entity signature and DNSid
  operational-key countersignature. This check is independent of `fl=logchk`.
- ISSUANCE must match the current TXT record: same DNSid FQDN, same `gi`, and
  accountable-entity public key material corresponding to current `ek`.
- The current `ku` key must either be the ISSUANCE operational key or be
  connected to it by a valid KEY_ROTATION continuity chain.
- `KEY_ROTATION` rotates only the operational key discovered through `ku`; TXT
  re-signing is required only when TXT tag values change.
- Accountable-entity key continuity, `ek` changes, `gi` changes, transfer, and
  recovery require future profile-defined continuity proof and must otherwise be
  treated as reissuance or local-policy risk.
- For publication, `BuildUnsignedRecord` emits the required and configured tags
  listed above and rejects identical entity and operational key thumbprints;
  `RecordSigningProvider` selects the entity provider, and
  `EncodeRecordSignature` returns unpadded base64url without an algorithm prefix.
- During verification, `ValidateVerifiedKeys` enforces the exactly-one-current
  operational-key rule and distinct entity/operational thumbprints.
  `HasStructuralGovernanceRelationship` compares the agent FQDN directly with
  `gi`; `VerifyLifecycleBinding` verifies bilateral ISSUANCE, including delegated
  cross-domain governance evidence when the structural check is false, and
  operational continuity.

### DnsIdTxtRecord

Holds the fields of a `_dnsid` TXT record. Provides serialization, deserialization, field validation, and canonical form construction for signature operations.

The authoritative parsed representation is the exact profile ID plus the parsed
tag map. Typed fields are ergonomic accessors over known tags, not permission to
reinterpret tags across profiles. Whether a field is required, optional, known,
ignored, or semantically meaningful is determined by the selected
[Identity Record Behavior Profile](#identity-record-behavior-profiles).

| Field        | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `v`          | string | yes      | Behavior profile selector. Must match a supported selector; see [Identity Record Behavior Profiles](#identity-record-behavior-profiles) and [Version String Convention](#version-string-convention). Must appear first on the wire and be preserved exactly for signature verification. The current publish profile emits `dnsid-draft-01`; pre-RFC `DNSid1` is verification-only. |
| `gi`         | string | profile-owned | Governance/accountable-entity identifier. In the draft 01 behavior, a lowercase ASCII DNS domain only. Future profiles may define other forms. |
| `ek`         | string | profile-owned | Accountable-entity record-signing key URI. Required by the draft 01 behavior; host must equal `gi` or be beneath it with DNS-label boundary matching. Verifies `sg` and accountable-entity lifecycle signatures. |
| `ku`         | string | profile-owned | Operational/runtime key URI. In the draft 01 behavior, an HTTPS URL whose host equals the identity FQDN and whose JWKS contains exactly one current operational signing key. |
| `lr`         | string | yes      | Log reference. Structured identifier: log technology + identity entry location. |
| `su`         | string | yes      | Status URI. HTTPS URL returning current lifecycle state. |
| `sg`         | string | yes      | Entity signature over the selected profile's `Canonical()` output. In the draft 01 behavior, unpadded base64url raw signature bytes with the algorithm determined by the single current `ek` JWK `alg`; algorithm-prefixed signatures are not accepted. |
| `fl`         | string | no       | Policy flags. Comma-separated. Defined values: `mtls`, `logchk`. |
| `ka`         | string | no       | Maximum signing key age. Values: `24h`, `7d`, `30d`, `90d`. |
| `cu`         | string | no       | Capabilities URI. HTTPS URL for AGENTS.md or Agent Card. |
| `tags`       | map[string]string | internal | Exact parsed tag map, preserving the profile-selected `v=` value and all known and unknown tags for profile dispatch, canonicalization, and serialization. |
| `unknownTags` | map[string]string | no | Syntactically valid extension tags not known to the selected profile. Preserved for canonical signature verification and serialization, but ignored for semantic validation. |
| `IdentityFQDN`  | string | internal | The identity's FQDN. Not a TXT record tag. Set during `Parse` from the DNS owner name (`_dnsid.<fqdn>`) or during construction via [`CreateTxtRecord`](01-core-identity-manager.md#core-methods). Used by `Validate` to enforce `gi` consistency and `ku` host matching. |

```
FUNCTION NormalizeFQDN(name: string) -> string
  // Converts IDNA U-labels to A-label punycode, lowercases ASCII, strips exactly one
  // trailing root dot for comparison/storage, and validates DNS label constraints.
  // Raises ValidationError if the name is empty, contains empty labels, has any label
  // over 63 octets, exceeds the 253-octet DNS presentation limit, or exceeds the
  // DNSid identity FQDN limit of 246 octets when used as an Identity FQDN.
  ascii = IDNA.ToASCII(name)
  ascii = LowercaseASCII(ascii)
  ascii = StripOneTrailingDot(ascii)
  ValidateDNSLabels(ascii)
  RETURN ascii
END

FUNCTION DnsIdTxtRecord.Canonical() -> string
  // Signature input defined by the selected behavior profile. For the draft 01
  // behavior, all known and unknown tags except sg are sorted alphabetically by
  // tag name, semicolon-separated, with no whitespace. The exact v value remains
  // in the sorted tag set; DNSid1 is never rewritten to dnsid-draft-01.
  // Unknown extension tags are ignored semantically but preserved for signatures.
  // Tags() omits unset/empty known optional tags, but preserves unknown tags even
  // when their value is empty (see Serialize note below).
  // The result is always pure ASCII: the spec ABNF (§4.2) constrains tag names to
  // ALPHA/DIGIT/"_" and tag values to printable ASCII (%x21-3A / %x3C-7E), so no
  // encoding ambiguity exists. Sign and verify over the raw ASCII bytes.
  // Published example: "ek=https://example.com/dnsid/entity-keys.json;fl=mtls;gi=example.com;ka=30d;ku=https://agent.example/dnsid/op-keys.json;lr=...;su=...;v=dnsid-draft-01"
  tags = SortAlphabetically(record.Tags().Exclude("sg"))
  RETURN Join(tags, ";")
END

FUNCTION DnsIdTxtRecord.KnownTagsCanonical() -> string
  // Profile-owned comparison form. For the draft 01 behavior, this uses the same
  // ordering as Canonical() but excludes unknownTags entirely.
  // Used by PublishClientControlledRecord to compare the registry-supplied
  // record against the locally-generated expected record: unknown tags
  // (e.g. registry-managed expiry) may legitimately differ and must not fail
  // the comparison.
  // MUST NOT be used as a signature input — signatures always use Canonical().
  tags = SortAlphabetically(record.KnownTags().Exclude("sg"))
  RETURN Join(tags, ";")
END

FUNCTION DnsIdTxtRecord.Serialize() -> string
  // DKIM-style tag=value string (RFC 6376 syntax), semicolon-separated.
  // Serialization is profile-owned. For all current profiles, v MUST appear
  // first; all other known and unknown tags follow in any order.
  // Empty known optional tags created by this SDK MUST be omitted — serializers MUST
  // NOT emit e.g. "fl=" for an unset policy flag. Parsed unknown extension tags,
  // including empty-valued unknown tags, MUST be preserved for canonical signature
  // verification and round-trip serialization.
  RETURN "v=" + record.v + ";" + Join(record.Tags().Exclude("v"), ";")
END

FUNCTION DnsIdTxtRecord.Parse(raw: string) -> DnsIdTxtRecord
  // raw is the concatenation of all DNS TXT RDATA strings (multi-string encoding per DNS spec).
  // The entire raw string must parse as exactly one DNSid record beginning with a
  // supported v= behavior profile selector; extra material, multiple records,
  // malformed tag-value elements, and unsupported v= values raise ParseError.
  //
  // Responsibility split: Parse resolves the behavior profile and enforces
  // profile syntax, required tags, and uniqueness. Validate enforces semantic
  // constraints that require IdentityFQDN context.
  pairs = Split(raw, ";")
  IF NOT StartsWith(pairs[0], "v=") THEN
    RAISE ParseError("v= tag must be first")
  END
  version = Split(pairs[0], "=", limit=2)[1]
  profile = ResolveIdentityRecordProfile(version)
  IF profile == nil THEN
    RAISE ParseError("unsupported DNSid TXT record profile: " + version)
  END
  seenTags = EmptySet()
  FOR i, pair in pairs
    IF pair == "" THEN
      IF i == len(pairs)-1 THEN
        CONTINUE  // optional trailing semicolon is valid
      END
      RAISE ParseError("empty TXT tag element")
    END
    IF i > 0 AND StartsWith(pair, " ") THEN
      pair = StripOneLeadingSpace(pair)  // ABNF permits exactly one SP after semicolon
    END
    IF NOT StringContains(pair, "=") THEN
      RAISE ParseError("TXT tag element missing '='")
    END
    tag, value = Split(pair, "=", limit=2)
    // Tag name rule (spec §4.2 ABNF): ALPHA *( ALPHA / DIGIT / "_" )
    IF NOT IsValidTagName(tag) THEN
      RAISE ParseError("invalid TXT tag name: " + tag)
    END
    // Tag value rule (spec §4.2 ABNF): *( %x21-3A / %x3C-7E )
    // i.e. printable ASCII excluding semicolon (0x3B) and space (0x20)
    IF NOT IsValidTagValue(value) THEN
      RAISE ParseError("invalid TXT tag value for tag: " + tag)
    END
    IF tag IN seenTags THEN
      RAISE ParseError("duplicate TXT tag: " + tag)
    END
    seenTags.Add(tag)
    IF tag is known by profile THEN
      record.SetKnownTag(tag, value)
      // SetKnownTag with an empty value for an optional tag is a no-op: the field
      // remains unset, equivalent to the tag being absent. Required tags are
      // profile-owned and missing/empty values are caught by ValidateRequiredTags below.
    ELSE
      record.unknownTags[tag] = value  // retained for Canonical() and Serialize()
    END
  END
  profile.ValidateRequiredTags(record)  // raises if required tags for this profile are missing/empty
  RETURN record
END

FUNCTION DnsIdTxtRecord.ParseUnsignedCanonical(raw: string) -> DnsIdTxtRecord
  // Parses the pre-signature canonical form produced by Canonical(). This is used only
  // by local signing workflows, such as PublishClientControlledRecord, where
  // the SDK must inspect registry-supplied canonical bytes before adding sg.
  // It applies the same structural checks as Parse except that sg MUST be absent,
  // tag order MUST already match
  // Canonical(), required non-signature tags MUST be present, and draft 01
  // canonical input places v according to alphabetical order rather than first.
  pairs = Split(raw, ";")
  parsed = EmptyMap()
  version = ""
  FOR i, pair in pairs
    IF pair == "" THEN
      IF i == len(pairs)-1 THEN
        CONTINUE
      END
      RAISE ParseError("empty TXT tag element")
    END
    IF i > 0 AND StartsWith(pair, " ") THEN
      pair = StripOneLeadingSpace(pair)
    END
    IF NOT StringContains(pair, "=") THEN
      RAISE ParseError("TXT tag element missing '='")
    END
    tag, value = Split(pair, "=", limit=2)
    IF tag == "sg" THEN
      RAISE ParseError("unsigned canonical DNSid record must not contain sg")
    END
    IF NOT IsValidTagName(tag) OR NOT IsValidTagValue(value) THEN
      RAISE ParseError("invalid TXT tag")
    END
    IF tag IN parsed THEN
      RAISE ParseError("duplicate TXT tag: " + tag)
    END
    parsed[tag] = value
    IF tag == "v" THEN
      version = value
    END
  END
  IF version == "" THEN
    RAISE ParseError("unsigned canonical DNSid record missing v tag")
  END
  profile = ResolveIdentityRecordProfile(version)
  IF profile == nil THEN
    RAISE ParseError("unsupported DNSid TXT record profile: " + version)
  END
  record = DnsIdTxtRecord{v: version}
  FOR tag, value in parsed.Exclude("v")
    IF tag is known by profile THEN
      record.SetKnownTag(tag, value)
    ELSE
      record.unknownTags[tag] = value
    END
  END
  profile.ValidateRequiredNonSignatureTags(record)
  IF record.Canonical() != raw THEN
    RAISE ParseError("unsigned DNSid record is not in canonical form")
  END
  RETURN record
END

FUNCTION DnsIdTxtRecord.PolicyFlags() -> Set<string>
  flags = EmptySet()
  IF record.fl == "" THEN
    RETURN flags
  END
  FOR token in Split(record.fl, ",")
    name = TrimSpace(token)
    IF name != "" THEN
      flags.Add(name)
    END
  END
  RETURN flags
END

FUNCTION DnsIdTxtRecord.Validate() -> error
  profile = ResolveIdentityRecordProfile(record.v)
  IF profile == nil THEN
    RETURN ValidationError("unsupported DNSid profile: " + record.v)
  END
  RETURN profile.Validate(record)
END

FUNCTION Draft01BehaviorProfile.Validate(record: DnsIdTxtRecord) -> error
  identityFQDN = NormalizeFQDN(record.IdentityFQDN)
  giDomain = NormalizeFQDN(record.gi)
  IF record.gi != giDomain THEN
    RETURN ValidationError("gi must be lowercase ASCII A-label domain")
  END

  ekURI = ParseURI(record.ek)
  IF ekURI.scheme != "https" OR ekURI.Hostname() == "" THEN
    RETURN ValidationError("ek must be a valid HTTPS URI with a host")
  END
  ekHost = NormalizeFQDN(ekURI.Hostname())
  IF ekHost != giDomain AND NOT HasSuffix(ekHost, "." + giDomain) THEN
    RETURN ValidationError("ek host must equal or be beneath gi")
  END

  kuURI = ParseURI(record.ku)
  IF kuURI.scheme != "https" OR kuURI.Hostname() == "" THEN
    RETURN ValidationError("ku must be a valid HTTPS URI with a host")
  END
  IF NormalizeFQDN(kuURI.Hostname()) != identityFQDN THEN
    RETURN ValidationError("ku host must equal identity FQDN")
  END

  suURI = ParseURI(record.su)
  IF suURI.scheme != "https" OR suURI.Hostname() == "" THEN
    RETURN ValidationError("su must be a valid HTTPS URI with a host")
  END

  IF record.cu != "" THEN
    cuURI = ParseURI(record.cu)
    IF cuURI.scheme != "https" OR cuURI.Hostname() == "" THEN
      RETURN ValidationError("cu must be a valid HTTPS URI with a host")
    END
  END

  IF record.ka != "" AND record.ka NOT IN ["24h", "7d", "30d", "90d"] THEN
    RETURN ValidationError("ka must be one of: 24h, 7d, 30d, 90d")
  END

  RETURN nil
END

FUNCTION DnsIdTxtRecord.GovernanceID() -> string
  // Returns the profile-selected governance/accountable-entity identifier.
  // The draft 01 behavior returns gi.
  RETURN record.gi
END

FUNCTION Draft01BehaviorProfile.HasStructuralGovernanceRelationship(record: DnsIdTxtRecord) -> bool
  identityFQDN = NormalizeFQDN(record.IdentityFQDN)
  giDomain = NormalizeFQDN(record.gi)
  RETURN identityFQDN == giDomain OR HasSuffix(identityFQDN, "." + giDomain)
  // A false result classifies a delegated cross-domain relationship. It does not
  // by itself reject the record: VerifyLifecycleBinding must prove that exact
  // relationship through bilateral ISSUANCE, or verification fails closed.
END

FUNCTION DnsIdTxtRecord.SignatureVerificationKeyURI() -> string
  // Returns the HTTPS URI for the JWKS used to verify this TXT record's sg
  // signature. The draft 01 behavior returns ek.
  RETURN record.ek
END

FUNCTION DnsIdTxtRecord.SignatureVerificationKeyAllowedHost() -> string
  // Returns the normalized allowed host for fetching the TXT signature
  // verification JWKS. The draft 01 behavior returns the gi domain boundary.
  RETURN NormalizeFQDN(record.gi)
END

FUNCTION DnsIdTxtRecord.SignatureVerificationKeyAllowsDomainBoundary() -> bool
  // The draft 01 behavior permits the initial ek host and redirects to remain at
  // or below gi with DNS-label boundary matching.
  RETURN true
END

FUNCTION DnsIdTxtRecord.RuntimeKeyURI() -> string
  // The draft 01 behavior uses ku for runtime/application verification.
  RETURN record.ku
END

FUNCTION DnsIdTxtRecord.RuntimeKeyAllowedHost() -> string
  // The draft 01 behavior requires ku host to equal the identity FQDN.
  RETURN NormalizeFQDN(record.IdentityFQDN)
END

FUNCTION DnsIdTxtRecord.KeyAgeSubjectThumbprint(recordSigningKey: JWK, runtimeJwks: JWKS) -> string
  // The draft 01 behavior applies ka to the single current operational key at ku.
  RETURN runtimeJwks.CurrentOperationalSigningKey(record.Profile()).Thumbprint()
END
```

---

### JWKS

Wrapper around a JWK Set document. Provides helpers for retrieving the current
protocol keys and general helpers for application-profile verification.

```
FUNCTION JWKS.SigningKeys() -> []JWK
  // Returns all keys suitable for application-layer signature verification where
  // a profile explicitly permits selecting among keys by kid/thumbprint. This is
  // not the draft 01 TXT-record verification rule.

FUNCTION JWKS.CurrentRecordSigningKey(profile: IdentityRecordProfile) -> JWK
  // For draft 01 ek JWKS: requires exactly one current signing key, with kid and alg,
  // supported key type, and use absent/sig. Raises if zero or more than one current
  // signing key is present, or if alg is missing/inconsistent.
  // Older profiles may delegate to SigningKeys() if their exact profile permits
  // trial verification across multiple keys.

FUNCTION JWKS.CurrentOperationalSigningKey(profile: IdentityRecordProfile) -> JWK
  // For draft 01 ku JWKS: same exactly-one-current-key rule as ek. Used for
  // runtime/application signatures, ka, ISSUANCE countersignatures, and
  // KEY_ROTATION continuity.

FUNCTION JWKS.KeyById(kid: string) -> JWK | nil
  // Returns the key matching the given kid, or nil if not found.

FUNCTION JWKS.ValidateRecordSigning(profile?: IdentityRecordProfile)
  // Raises if the record-signing key set violates the selected profile. For
  // Draft 01 ek live endpoints require exactly one current signing key,
  // required kid, required alg, supported key type, and alg/key consistency.

FUNCTION JWKS.ValidateOperational(profile?: IdentityRecordProfile)
  // Raises if the operational key set violates the selected profile. For draft 01
  // ku live endpoints, this includes exactly one current signing key, required
  // kid, required alg, supported key type, and alg/key consistency. Older SDK
  // profiles may permit absent alg where kty/crv unambiguously determines it.

FUNCTION JWK.SignatureAlg(profile?: IdentityRecordProfile) -> string
  // Returns the JOSE signature algorithm compatible with this key. For draft 01,
  // alg MUST be present and consistent with kty/crv. Older profiles may derive
  // the compatible algorithm from unambiguous kty/crv bindings if their profile
  // allows omitted alg: OKP/Ed25519 -> EdDSA, EC/P-256 -> ES256.

FUNCTION ParseRecordSignature(record: DnsIdTxtRecord) -> ParsedSignature
  // Profile-owned sg parsing. Draft 01 parses sg as bare unpadded base64url raw
  // signature bytes and takes alg from the single current ek JWK.

FUNCTION JWK.Thumbprint() -> string
  // RFC 7638 JWK thumbprint of the key. Implementations MUST use the RFC 7638
  // algorithm (SHA-256 over the canonical JSON of the required public members).
  // Returns unpadded base64url (RFC 7515 §2).
  //
  // Lifecycle log bindings (ISSUANCE, KEY_ROTATION events) MUST use thumbprints,
  // not kid values, as the durable key identifier. kid may differ across systems or
  // change during key management operations; the thumbprint is stable for the same
  // key pair and is the only identifier that can be reliably matched across DNS,
  // JWKS, and log records.
END
```

JWK fields used by DNSid:

| Field | Required | Description |
|-------|----------|-------------|
| `kid` | yes for draft 01 live keys | Key identifier. |
| `alg` | yes for draft 01 live keys | JOSE algorithm metadata. Must match the key's kty/crv binding. ES256 (EC, crv=P-256) is mandatory; Ed25519 should be supported. |
| `use` | no | Key usage. When present on a signing key, MUST be `sig`. Accountable-entity and operational roles are established by the `ek` and `ku` endpoints, not by custom JWK metadata. |

---

### VerifiedDomain

The result of a successful
[`VerifyDomain`](01-core-identity-manager.md#core-methods) call. Contains all
verified data for the domain and ergonomic accessors. It is not a durable
acceptance or authorization assertion: the manager evaluates configured
[counterparty acceptance](01-core-identity-manager.md#counterparty-acceptance)
per invocation, including cache hits. No `trusted` flag or cached policy decision
belongs in this type.

Fields:

| Field            | Type          | Description |
|------------------|---------------|-------------|
| `domain`         | string        | Verified FQDN / identity identifier |
| `record`         | DnsIdTxtRecord | Parsed and validated `_dnsid` TXT record |
| `jwks`           | JWKS          | Runtime/application key set selected by the profile. For draft 01, fetched from `ku` after `sg` is verified through `ek`. |
| `recordSigningJwks` | JWKS       | Key set used to verify the `_dnsid` TXT `sg` signature. For draft 01, fetched from `ek`. |
| `signingKey`     | JWK           | The specific accountable-entity record-signing key that validated `sg`. For draft 01, this is not a runtime/application key. |
| `tlsCert`        | TLSCertificate | TLS certificate presented by the profile-selected runtime/application key endpoint. For draft 01, this is the `ku` endpoint certificate and supplies the live identity-FQDN TLS proof for cache expiry. |
| `recordSigningTlsCert` | TLSCertificate | TLS certificate presented by the profile-selected TXT signature verification key endpoint. For draft 01, this is the `ek` endpoint certificate and bounds cached record-signing material. |
| `registryStatus` | AgentStatus   | State returned by the most recent `su` endpoint fetch; confirmed ACTIVE before full verification succeeds and refreshed on cache hits according to `statusCheckInterval`. |
| `verifiedAt`         | timestamp     | Time the full verification (DNS + JWKS + TLS + signature) was performed |
| `dnsTTL`             | duration      | Remaining TTL of the `_dnsid` TXT response at acquisition; zero means no reuse beyond the acquiring operation. |
| `dnsExpiresAt`       | timestamp (internal metadata) | Absolute DNS expiry established at acquisition, not at verification completion. Bindings may retain equivalent timing without exposing a new public field. |
| `keyBoundAt`         | timestamp     | Timestamp of the ISSUANCE or KEY_ROTATION event that introduced the profile-selected runtime/application key; zero value if `ka` tag is absent |
| `lastStatusCheckAt`  | timestamp     | Time the `su` status endpoint was last fetched. Updated on every full verification and on each status-only re-fetch during cache hits. `VerifyDomain` re-fetches `su` when `Now() - lastStatusCheckAt >= config.verification.statusCheckInterval`. |
| `dnssecState`        | DNSSECState   | DNSSEC validation outcome for the `_dnsid` TXT record response. Callers SHOULD surface this in audit logs and policy decisions. See [DNSSECState](#dnssecstate). |
| `logReader`          | LogReader     | Bound to `record.lr`; created eagerly during `VerifyDomain`. A `NoopLogReader` when no factory is registered for the counterparty's log method — log-dependent operations raise with a descriptive error only if called. See [LogReader](06-log-bindings.md#logreader-interface). |

```
FUNCTION VerifiedDomain.CachedState() -> string
  // Returns the identity state from the most recent su fetch. This reflects the state
  // at lastStatusCheckAt, not necessarily right now. For a live status check before
  // a new operation, call VerifyDomain again (or set statusCheckInterval to zero).
  RETURN registryStatus.state

FUNCTION VerifiedDomain.RequiresLogCheck() -> bool
  // Reports the record's logchk policy signal. It does not classify the caller's
  // operation or perform network I/O.
  RETURN record.PolicyFlags().Has("logchk")

FUNCTION VerifiedDomain.Expiry() -> timestamp
  candidates = []

  // DNS TTL: record may have changed (key rotation, re-sign, policy update)
  candidates.append(dnsExpiresAt)  // acquisition time + remaining TTL, never restarted

  // TLS certificates: certs proved live control of fetched key material; stale after NotAfter
  candidates.append(tlsCert.NotAfter)
  candidates.append(recordSigningTlsCert.NotAfter)

  // Key age bound: if ka is set, key is rejected after keyBoundAt + ka duration
  IF record.ka != "" AND keyBoundAt != ZeroTime THEN
    candidates.append(keyBoundAt + ParseDuration(record.ka))
  END

  RETURN Min(candidates)
  // Note: spec-strict interactive operations require a fresh status endpoint check
  // before each new operation. That requires statusCheckInterval == 0 or an explicit
  // status refresh. Expiry() governs when non-status cached material must be refreshed.
```

---

### `_dnsid` TXT Record

[Reference](https://datatracker.ietf.org/doc/draft-ihsanullah-dnsid/)

A TXT record set at `_dnsid.{fqdn}`. Syntax follows RFC 6376 (DKIM) tag=value format, semicolon-separated. `v` must be the first tag.

#### Format Rules

- Tag names are case-sensitive.
- Duplicate tag names are prohibited; a record containing duplicates must be treated as invalid.
- Unknown syntactically valid tags must be preserved for canonical signature verification and serialization, but ignored for semantic validation.
- DNS TXT RDATA may span multiple 255-octet strings; implementations must concatenate all strings before parsing.
- If more than one TXT record exists at `_dnsid.{fqdn}`, verification must fail.
- `Canonical()` signature input is profile-owned. In draft 01, it includes every tag except `sg` sorted alphabetically by tag name with semicolon separators and no whitespace. The exact `v=` selector participates unchanged.

#### Version String Convention

The on-the-wire `v=` value is the record's behavior selector. Submitted IETF
drafts use `dnsid-draft-<nn>`, where `<nn>` is the two-digit IETF draft revision,
for example `dnsid-draft-01`. Numbered selectors are immutable: a verifier that
supports draft 02 still verifies `dnsid-draft-01` using frozen draft 01 behavior.

Pre-submission snapshots do not receive public wire selectors. Implementations
MUST NOT derive selectors from local git dates, release dates, current time, or
string ordering, and released SDKs MUST NOT accept or publish dated selectors.
Work against an unpublished next draft remains isolated from release branches.

While version 1 remains an Internet-Draft, `DNSid1` is a verification-only
selector for the latest submitted draft fully supported by that SDK release. It
remains the exact signed wire value: implementations share behavior with the
selected numbered profile but never rewrite the record before canonicalization
or signature verification. The current release maps it to `dnsid-draft-01` behavior.

The current default and only publish profile is `dnsid-draft-01`. When a later
draft is submitted and fully supported, SDK and registry releases advance the
default to that exact numbered selector. They continue to verify older numbered
selectors they advertise, without changing those selectors' behavior.

When version 1 becomes an RFC, `DNSid1` freezes permanently to the RFC behavior
and becomes the version 1 publish selector. A future revised standard uses
`DNSid2`; `DNSid1` does not continue to mean latest after RFC publication.

Verifiers MUST resolve `v=` to behavior they implement and MUST reject any other
value using a non-retryable parse error that names the unsupported selector. They
MUST preserve the exact parsed `v=` value for canonical signature verification.
For SDK error semantics, see [ParseError](01-core-identity-manager.md#parseerror).

#### Tags

The SDK data model is the [`DnsIdTxtRecord`](#dnsidtxtrecord) table above.
Normative required/optional tag status and tag behavior are defined by the
selected [Identity Record Behavior Profile](#identity-record-behavior-profiles).

### DNSid Key Service JWKS Records

[Reference RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.txt)

The draft 01 behavior defines two HTTPS JWKS services: `ek` for accountable-entity record-signing keys and `ku` for DNSid operational/runtime keys. The protocol does not define or require a `.well-known` path; the TXT record carries complete URLs. Both endpoints must be served over HTTPS with valid TLS certificates for their URI hosts. The `ku` host must equal the identity FQDN, and the `ek` host must equal `gi` or be beneath it with DNS-label boundary matching.

| Field | Required | Description |
|-------|----------|-------------|
| `kid` | yes | Key identifier. Draft 01 live `ek` and `ku` JWKS responses each contain exactly one current signing key with `kid`. |
| `alg` | yes for draft 01 | JOSE algorithm metadata. **ES256 (ECDSA P-256) is mandatory**. Ed25519 should be supported. |
| `use` | no | Key usage. When present on a signing key, MUST be `sig`. |

### TLS Certificate

[Reference TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246) | [Reference TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) | [Reference RFC 9525 — TLS Server Identity](https://www.rfc-editor.org/rfc/rfc9525)

| Field | Description |
|-------|-------------|
| `SAN` | Subject Alternative Name. Must include a `dNSName` SAN matching the endpoint URI host. |

All HTTPS endpoints must be fetched with full TLS certificate verification per RFC 9525. Identity verification rules:
- The expected endpoint host MUST be matched against `dNSName` entries in the Subject Alternative Name extension only. Common Name (`CN`) fallback is explicitly prohibited.
- Wildcard SANs are handled per RFC 9525 §6.3: a single leading `*` may match exactly one DNS label; wildcards in non-leftmost labels or matching multiple labels are not permitted.
- FQDN comparison MUST use the normalized form produced by `NormalizeFQDN()` (IDNA A-label, lowercased, no trailing dot). Implementations MUST NOT perform case-sensitive or byte-for-byte string comparison on raw certificate values without normalization.

Redirect and fetch rules:
- DNSid URI fetches MUST require HTTPS, verify TLS certificates, and reject non-HTTPS redirects.
- `VerifyDomain` fetches the profile-selected TXT signature verification JWKS URI, the runtime/application JWKS URI when distinct, and `su`; `cu` is not part of trust establishment.
- In draft 01, `ek` uses `HTTPSFetcher.FetchStrictJSON(record.ek, allowedHost=record.gi, domainBoundary=true)`; its certificate must cover the actual URI host, and the initial host and every redirect must remain equal to or beneath `gi` with DNS-label boundary matching.
- In draft 01, `ku` uses `HTTPSFetcher.FetchStrictJSON(record.ku, allowedHost=domain, domainBoundary=false)`; its certificate must cover the identity FQDN, and any redirect away from the identity FQDN MUST fail.
- `su` permits host-changing HTTPS redirects unless local policy is stricter.
- In draft 01, the `ku` JWKS fetch supplies the live FQDN TLS proof because `ku` host MUST equal the identity FQDN.
- When `mtls` is present, the peer certificate from the caller's application connection must validate against the identity FQDN with the same RFC 9525 rules. DNSid does not provision that certificate or require it to contain or bind to the `ku` key.

SDK-managed HTTPS requests honor transport configuration without changing protocol semantics. When `TransportConfig.dnsServer` is set, implementations use it for HTTPS origin name resolution for JWKS fetches, status refreshes, registry API calls, and DNSid HTTP transport helpers. When `TransportConfig.caBundlePath` is set, implementations add that CA bundle to the platform trust store for those HTTPS requests. These controls are deployment conveniences only: they do not alter signed TXT record contents, signature inputs, host-matching requirements, or TLS certificate verification rules.

### AgentStatus

Concrete JSON response profile used by this SDK for the `su` (status) endpoint. The DNSid protocol specification defines the status service semantics and required response properties, not a mandatory wire schema. This SDK profile is one conforming JSON representation of those semantics.

| Field                | Type      | Required                        | Description |
|----------------------|-----------|---------------------------------|-------------|
| `state`              | string    | yes                             | Current lifecycle state. One of: `PENDING`, `PROVISIONING`, `VERIFYING`, `ACTIVE`, `RETIRED`, `REVOKED`. |
| `lastTransitionAt`   | timestamp | yes                             | Time of the most recent state transition. |
| `revocationReason`   | string    | conditionally required          | Reason code. One of: `keyCompromise`, `policyViolation`, `superseded`, `cessationOfOperation`. Required when `state` is `REVOKED`; enforced at runtime by `AgentStatus.Validate()`. |

The endpoint MUST be served over HTTPS with a valid TLS certificate. `VerifyDomain` validates this SDK's JSON profile and rejects any response where `state != "ACTIVE"`. An unreachable endpoint produces a transient `StatusUnavailable` / protocol `INDETERMINATE` result, not verified-ACTIVE. Implementations that support another status-service profile MUST map it into `AgentStatus` or provide an equivalent validator before the ACTIVE check.

When the `su` host is outside the `gi` domain boundary, callers and audit output
SHOULD treat its response as delegated operational status rather than a direct
accountable-entity declaration. The base profile defines no stronger signed
status-delegation mechanism.

```
FUNCTION AgentStatus.Validate() -> error
  IF state NOT IN ["PENDING", "PROVISIONING", "VERIFYING", "ACTIVE", "RETIRED", "REVOKED"] THEN
    RETURN ValidationError("unknown agent status state: " + state)
  END
  IF lastTransitionAt == ZeroTime THEN
    RETURN ValidationError("lastTransitionAt is required")
  END
  IF state == "REVOKED" THEN
    IF revocationReason NOT IN ["keyCompromise", "policyViolation", "superseded", "cessationOfOperation"] THEN
      RETURN ValidationError("valid revocationReason is required when state is REVOKED")
    END
  END
  RETURN nil
END
```

## Application Profile Data Types

Application-profile data types such as
[`JWTOptions`](03-jose-jwt-jws.md#public-surface),
[`HttpSigningOptions`](02-rfc9421-http-message-signatures.md#dnsid-request-profile),
and `SignatureParams` are owned by their profile documents unless they become
shared across multiple profiles.
