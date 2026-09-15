// dnsid-ts compliance shim: reads a JSON array of requests on stdin, writes a
// JSON array of normalized results on stdout (see compliance-tests/README.md).
// Zero dependencies of its own — dynamically imports the built dnsid-ts dist,
// located via the DNSID_TS_DIR environment variable.
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign as signBytes, verify as verifyBytes } from 'node:crypto';
import process from 'node:process';

const sdkDir = process.env.DNSID_TS_DIR;
if (!sdkDir) {
  console.error('DNSID_TS_DIR is not set');
  process.exit(2);
}
// Monorepo layout (@identity-digital/dnsid-protocol owns DnsIdTxtRecord and
// normalizeFQDN) first, legacy single-package layout second.
const candidates = [
  join(sdkDir, 'packages', 'core', 'dist', 'index.js'),
  join(sdkDir, 'dist', 'index.js'),
];
const entry = candidates.find((p) => existsSync(p));
if (!entry) {
  console.error(`no built dnsid-ts entry point found; tried: ${candidates.join(', ')} — run npm ci && npm run build in ${sdkDir}`);
  process.exit(2);
}
const sdk = await import(pathToFileURL(entry).href);
const { DnsIdTxtRecord, DomainLog, IdentityManager, JWKS, jwkSignatureAlg, jwkThumbprint, normalizeFQDN, validateAgentStatus } = sdk;
const sdkFacadeEntry = join(sdkDir, 'packages', 'sdk', 'dist', 'index.js');
const sdkFacade = existsSync(sdkFacadeEntry) ? await import(pathToFileURL(sdkFacadeEntry).href) : null;
const c2spEntry = join(sdkDir, 'packages', 'log-c2sp-tlog', 'dist', 'index.js');
const c2sp = existsSync(c2spEntry) ? await import(pathToFileURL(c2spEntry).href) : null;
const httpSignaturesEntry = join(sdkDir, 'packages', 'http-signatures', 'dist', 'index.js');
const httpSignatures = existsSync(httpSignaturesEntry) ? await import(pathToFileURL(httpSignaturesEntry).href) : null;

const optional = (v) => (v === undefined || v === '' ? null : v);

function recordJSON(r) {
  return {
    v: r.v,
    gi: optional(r.gi),
    oi: optional(r.oi), // no draft-00 support; null unless a future profile adds it
    ek: optional(r.ek),
    ku: optional(r.ku),
    lr: optional(r.lr),
    su: optional(r.su),
    sg: optional(r.sg),
    fl: optional(r.fl),
    ka: optional(r.ka),
    cu: optional(r.cu),
    unknown: Object.fromEntries(r.unknownTags ?? new Map()),
  };
}

const errJSON = (e) => ({
  ok: false,
  error: e?.name && e.name !== 'Error' ? e.name : 'Error',
  message: String(e?.message ?? e),
});

function fixtureKeyProvider(fixture) {
  const jwk = { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig', kid: fixture.kid, x: fixture.x };
  const privateKey = createPrivateKey({ key: { ...jwk, d: fixture.seed }, format: 'jwk' });
  const state = { signedPayload: new Uint8Array(), signCalls: 0 };
  return {
    jwk,
    privateKey,
    state,
    provider: {
      signingKey: async () => jwk,
      jwk: async () => jwk,
      listKeyIds: async () => [fixture.kid],
      sign: async (payload) => {
        state.signCalls += 1;
        state.signedPayload = payload;
        return signBytes(null, payload, privateKey);
      },
      signKey: async (_kid, payload) => signBytes(null, payload, privateKey),
      generateKey: async () => { throw new Error('not implemented'); },
      activate: async () => { throw new Error('not implemented'); },
      supersede: async () => { throw new Error('not implemented'); },
    },
  };
}

async function createTxtRecord(req) {
  const entity = req.entityKey ? fixtureKeyProvider(req.entityKey) : null;
  const operational = fixtureKeyProvider(req.sameKey ? req.entityKey : req.operationalKey);
  const manager = new IdentityManager({ identity: req.config }, { keyProvider: operational.provider, entityKeyProvider: entity?.provider });
  const record = DnsIdTxtRecord.parse(await manager.createTxtRecord());
  const signature = Buffer.from(record.sg, 'base64url');
  const payload = entity.state.signedPayload;
  return {
    ok: true,
    record: recordJSON(record),
    signedPayload: new TextDecoder().decode(payload),
    signatureSource: entity.state.signCalls === 1 && operational.state.signCalls === 0 ? 'entity' : 'other',
    signatureVerified:
      verifyBytes(null, payload, createPublicKey(entity.privateKey), signature)
      && !verifyBytes(null, payload, createPublicKey(operational.privateKey), signature),
  };
}

async function handle(req) {
  try {
    switch (req.op) {
      case 'http_signature_base': {
        try {
          if (!httpSignatures) throw new Error('HTTP signatures package is not built');
          const message = new Request(req.request.url, {
            method: req.request.method,
            headers: req.request.headers,
          });
          const params = httpSignatures.parseSignatureInput(req.signature_input).get(req.label);
          if (!params) throw new Error(`signature label ${req.label} not found`);
          return { ok: true, value: new TextDecoder().decode(httpSignatures.buildSignatureInput(message, params)) };
        } catch (error) {
          return { ok: false, error: 'ConformanceError', message: String(error?.message ?? error) };
        }
      }
      case 'lifecycle_vector': return lifecycleVector(req);
      case 'c2sp_lifecycle_vector': return c2spLifecycleVector(req);
      case 'c2sp_managed_trust_select': {
        try {
          if (!c2sp) throw new Error('C2SP package is not built');
          const registry = await c2sp.createDnsidManagedVerificationRegistry();
          registry.newReader(req.lr);
          return { ok: true, trustMode: 'trust-profile' };
        } catch (error) {
          return { ok: false, error: 'ConformanceError', message: String(error?.message ?? error) };
        }
      }
      case 'sdk_conformance': {
        if (!sdkFacade) throw new Error('SDK package is not built');
        const value = sdkFacade.SDK_CONFORMANCE;
        return {
          ok: true,
          ...value,
          immutable: Object.isFrozen(value)
            && Object.isFrozen(value.verificationProfiles)
            && Object.isFrozen(value.logBindings)
            && Object.isFrozen(value.knownDeviations),
        };
      }
      case 'create_txt_record': return await createTxtRecord(req);
      case 'agent_status_evaluate': {
        const status = validateAgentStatus(req.status);
        return { ok: true, state: status.state, verificationAccepted: status.state === 'ACTIVE' };
      }
      case 'parse': {
        const r = DnsIdTxtRecord.parse(req.raw);
        return { ok: true, record: recordJSON(r) };
      }
      case 'canonical': {
        const r = DnsIdTxtRecord.parse(req.raw);
        return { ok: true, value: r.canonical() };
      }
      case 'roundtrip': {
        const r = DnsIdTxtRecord.parse(req.raw);
        const serialized = r.serialize();
        let r2;
        try {
          r2 = DnsIdTxtRecord.parse(serialized);
        } catch (e) {
          return { ok: false, error: 'RoundTripError', message: `reparse failed: ${e.message}` };
        }
        return { ok: true, record: recordJSON(r2), value: serialized };
      }
      case 'validate': {
        const r = DnsIdTxtRecord.parse(req.raw);
        r.agentFQDN = req.identity_fqdn;
        r.validate();
        return { ok: true, record: recordJSON(r) };
      }
      case 'normalize_fqdn': {
        return { ok: true, value: normalizeFQDN(req.name, true) };
      }
      case 'jwk_thumbprint': {
        return { ok: true, value: await jwkThumbprint(req.jwk) };
      }
      case 'jwk_signature_alg': {
        return { ok: true, value: jwkSignatureAlg(req.jwk) };
      }
      case 'jwks_validate': {
        new JWKS(req.jwks.keys).validate();
        return { ok: true };
      }
      case 'jwks_signing_keys': {
        const keys = new JWKS(req.jwks.keys).signingKeys();
        return { ok: true, value: keys.map((key) => key.kid ?? '') };
      }
      case 'jwks_key_by_id': {
        const key = new JWKS(req.jwks.keys).keyById(req.kid);
        return { ok: true, value: key?.kid ?? null };
      }
      default:
        return { ok: false, error: 'ShimError', message: `unknown op: ${req.op}` };
    }
  } catch (e) {
    return errJSON(e);
  }
}

const vectorKey = (label) => ({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: label, x: createHash('sha256').update(label).digest().subarray(0, 32).toString('base64url') });

async function lifecycleEvent(raw, key) {
  const common = { type: raw.type, domain: raw.domain, timestamp: new Date(raw.timestamp) };
  if (raw.type === 'ISSUANCE') {
    const entity = await key(raw.initialEntityPublicKey);
    const operational = await key(raw.initialOperationalPublicKey);
    const entityThumb = raw.initialEntityThumbprint ? await key(`jwk:${raw.initialEntityThumbprint}`) : undefined;
    const operationalThumb = raw.initialOperationalThumbprint ? await key(`jwk:${raw.initialOperationalThumbprint}`) : undefined;
    return { ...common, governanceId: raw.governanceId, initialEntityPublicKey: entity?.jwk, initialEntityThumbprint: entityThumb?.thumbprint, initialOperationalPublicKey: operational?.jwk, initialOperationalThumbprint: operationalThumb?.thumbprint };
  }
  if (raw.type === 'KEY_ROTATION') {
    const previous = raw.previousOperationalThumbprint ? await key(`jwk:${raw.previousOperationalThumbprint}`) : undefined;
    const next = await key(raw.newOperationalPublicKey);
    const nextThumb = raw.newOperationalThumbprint ? await key(`jwk:${raw.newOperationalThumbprint}`) : undefined;
    return { ...common, previousOperationalThumbprint: previous?.thumbprint, newOperationalPublicKey: next?.jwk, newOperationalThumbprint: nextThumb?.thumbprint };
  }
  if (raw.type === 'REVOCATION') return { ...common, reason: raw.reason };
  if (raw.type === 'MIGRATION') return { ...common, previousLog: raw.previousLog, newLog: raw.newLog, finalEntryRef: raw.finalEntryRef };
  if (raw.type === 'DELEGATION') return { ...common, delegatee: raw.delegatee, scope: raw.scope, expiry: new Date(raw.expiry) };
  return common;
}

async function lifecycleVector(req) {
  const keys = new Map();
  const reverse = new Map();
  const key = async (ref) => {
    if (!ref) return undefined;
    const label = ref.replace(/^jwk:/, '');
    if (!keys.has(label)) {
      const jwk = vectorKey(label);
      const thumbprint = await jwkThumbprint(jwk);
      keys.set(label, { jwk, thumbprint });
      reverse.set(thumbprint, label);
    }
    return keys.get(label);
  };
  const events = await Promise.all(req.events.map((event) => lifecycleEvent(event, key)));
  const at = req.at ? new Date(req.at) : new Date(8.64e15);
  try {
    const snapshot = new DomainLog(req.domain, events).snapshotAt(at);
    return { ok: true, identityState: snapshot.historicalState, activeOperationalThumbprint: reverse.get(snapshot.activeKeyThumbprint) ?? snapshot.activeKeyThumbprint, eventCount: snapshot.events.length, inheritedEventCount: 0, governanceId: snapshot.governanceId, keyBoundAt: Math.floor(snapshot.keyBoundAt.getTime() / 1000) };
  } catch (e) {
    let failingEventIndex;
    for (let i = 0; i < events.length; i++) {
      try { new DomainLog(req.domain, events.slice(0, i + 1)).snapshotAt(at); }
      catch (prefixError) { if (prefixError?.errorCategory === e?.errorCategory) { failingEventIndex = i; break; } }
    }
    return { ok: false, error: 'LifecycleError', message: String(e?.message ?? e), errorCategory: e?.errorCategory, ...(failingEventIndex === undefined ? {} : { failingEventIndex }) };
  }
}

async function c2spLifecycleVector(req) {
  if (!c2sp) return { ok: false, error: 'ShimError', message: 'C2SP package is not built' };
  if (!req.checkpointAccepted) return { ok: false, error: 'LifecycleError', message: 'accepted checkpoint failed', errorCategory: 'INVALID_EVIDENCE' };
  if (!req.completeThroughCheckpoint) return { ok: false, error: 'LifecycleError', message: 'stream is incomplete', errorCategory: 'INCOMPLETE_STREAM' };
  const effects = new Map();
  const ignored = [];
  const entries = [];
  const policy = c2sp.parseC2spPolicyFile(req.policy);
  const parsed = c2sp.parseC2spTlogLr(req.lr);
  for (const item of req.entries) {
    const bytes = Buffer.from(item.entry, 'base64url');
    const proof = Buffer.from(item.proof, 'base64url').toString('utf8');
    let verifiedProof;
    try {
      verifiedProof = c2sp.verifyC2spTlogProof(
        bytes,
        proof,
        policy,
        parsed.origin,
        parsed.scope,
        req.checkpointIntegrationTimeMs,
      );
    } catch (error) {
      if (!(error instanceof c2sp.C2spTlogError)) throw error;
      ignored.push(item.index);
      continue;
    }
    if (verifiedProof.index !== item.index) {
      ignored.push(item.index);
      continue;
    }
    entries.push({ index: item.index, bytes });
    effects.set(item.index, item.effectId);
  }
  const entityKey = req.entityJwk;
  const operationalKey = req.operationalJwk;
  const priorEvent = { type: 'ISSUANCE', domain: req.domain, governanceId: 'example', timestamp: new Date(0), initialEntityPublicKey: entityKey, initialEntityThumbprint: await jwkThumbprint(entityKey), initialOperationalPublicKey: operationalKey, initialOperationalThumbprint: await jwkThumbprint(operationalKey) };
  const verifyMigration = req.priorHistoryVerified === undefined || req.priorHistoryVerified === null ? undefined : async () => {
    if (!req.priorHistoryVerified) throw new Error('prior migration history unavailable');
    return { entityKey, activeOperationalKey: operationalKey, priorEvents: [priorEvent] };
  };
  const options = { scope: 'public', logOrigin: parsed.origin, streamId: parsed.streamId, lr: req.lr, signerKey: entityKey, checkpointIntegrationTimeMs: req.checkpointIntegrationTimeMs, verifyMigration };
  try {
    const selected = await c2sp.verifyStreamLifecycle(entries, req.domain, options);
    const appliedIndexes = selected.map((item) => item.index);
    const appliedEffectIds = appliedIndexes.map((index) => effects.get(index));
    for (const item of req.entries) if (!appliedIndexes.includes(item.index) && !ignored.includes(item.index)) ignored.push(item.index);
    const out = { ok: true, appliedEffectIds, ignoredCandidateIndexes: ignored.sort((a, b) => a - b) };
    const last = selected.at(-1)?.event.type;
    if (last === 'REVOCATION') out.identityState = 'REVOKED';
    if (last === 'RETIREMENT') out.identityState = 'RETIRED';
    if (selected[0]?.event.type === 'MIGRATION') out.stitchedEffectIds = [...req.priorAppliedEffectIds, ...appliedEffectIds];
    return out;
  } catch (e) {
    let failingCandidateIndex = e?.failingCandidateIndex;
    if (failingCandidateIndex === undefined) {
      for (let i = 0; i < entries.length; i++) {
        try { await c2sp.verifyStreamLifecycle(entries.slice(0, i + 1), req.domain, options); }
        catch (prefixError) { if ((prefixError?.errorCategory ?? 'INVALID_MIGRATION') === (e?.errorCategory ?? 'INVALID_MIGRATION')) { failingCandidateIndex = entries[i].index; break; } }
      }
    }
    return { ok: false, error: 'LifecycleError', message: String(e?.message ?? e), errorCategory: e?.errorCategory ?? 'INVALID_MIGRATION', ...(failingCandidateIndex === undefined ? {} : { failingCandidateIndex }) };
  }
}

let input = '';
for await (const chunk of process.stdin) input += chunk;
const requests = JSON.parse(input);
process.stdout.write(JSON.stringify(await Promise.all(requests.map(handle))) + '\n');
