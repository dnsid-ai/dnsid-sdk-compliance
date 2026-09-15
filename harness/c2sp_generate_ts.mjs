import { createPrivateKey, createPublicKey, sign as signEd25519 } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const sdkDir = process.env.DNSID_TS_DIR;
if (!sdkDir) throw new Error('DNSID_TS_DIR is not set');
if (process.argv.length < 3 || process.argv.length > 4) {
  throw new Error('usage: c2sp_generate_ts.mjs CORPUS [--countersign]');
}

const c2sp = await import(pathToFileURL(join(
  sdkDir,
  'packages/log-c2sp-tlog/dist/index.js',
)).href);
const protocol = await import(pathToFileURL(join(
  sdkDir,
  'packages/core/dist/index.js',
)).href);
const corpus = JSON.parse(await readFile(process.argv[2], 'utf8'));

function fixedKey(spec) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, spec.ed25519_seed_byte),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicJwk = {
    ...createPublicKey(privateKey).export({ format: 'jwk' }),
    alg: 'EdDSA',
    kid: spec.kid,
  };
  const provider = {
    async jwk(kid) {
      if (kid !== publicJwk.kid) throw new Error(`unexpected kid: ${kid}`);
      return publicJwk;
    },
    async signKey(kid, bytes) {
      if (kid !== publicJwk.kid) throw new Error(`unexpected kid: ${kid}`);
      return signEd25519(null, Buffer.from(bytes), privateKey);
    },
  };
  return { privateKey, provider, publicJwk };
}

const entity = fixedKey(corpus.keys.entity);
const initial = fixedKey(corpus.keys.operational_initial);
const rotated = fixedKey(corpus.keys.operational_rotated);
const entityThumb = await protocol.jwkThumbprint(entity.publicJwk);
const initialThumb = await protocol.jwkThumbprint(initial.publicJwk);
const rotatedThumb = await protocol.jwkThumbprint(rotated.publicJwk);
const issuanceSpec = corpus.events.issuance;

const issuanceEvent = {
  type: 'ISSUANCE',
  domain: corpus.domain,
  governanceId: corpus.governance_id,
  initialOperationalKid: initial.publicJwk.kid,
  initialOperationalAlg: initial.publicJwk.alg,
  initialOperationalPublicKey: initial.publicJwk,
  initialOperationalThumbprint: initialThumb,
  initialEntityKid: entity.publicJwk.kid,
  initialEntityAlg: entity.publicJwk.alg,
  initialEntityPublicKey: entity.publicJwk,
  initialEntityThumbprint: entityThumb,
  timestamp: new Date(issuanceSpec.timestamp * 1000),
};
const issuanceContext = {
  expectedFqdn: corpus.domain,
  expectedGovernanceId: corpus.governance_id,
  entityKey: entity.publicJwk,
  operationalKey: initial.publicJwk,
};
let issuance = c2sp.prepareC2spTlogEventForSigning(issuanceEvent, corpus.lr);
issuance = await c2sp.signPreparedC2spTlogEvent(
  issuance,
  'Entity',
  entity.provider,
  issuanceContext,
);
const entitySignedIssuance = Buffer.from(c2sp.canonicalBytes(issuance.envelope)).toString('base64url');

if (process.argv[3] === '--countersign') {
  const input = JSON.parse(await new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  }));
  let received = await c2sp.parsePreparedC2spTlogEvent(
    Buffer.from(input.prepared, 'base64url'),
    corpus.lr,
    issuanceContext,
  );
  received = await c2sp.signPreparedC2spTlogEvent(
    received,
    'OperationalCountersignature',
    initial.provider,
    issuanceContext,
  );
  const entry = await c2sp.c2spTlogEntryBytes(received, issuanceContext);
  process.stdout.write(JSON.stringify({ entry: Buffer.from(entry).toString('base64url') }));
  process.exit(0);
}

issuance = await c2sp.signPreparedC2spTlogEvent(
  issuance,
  'OperationalCountersignature',
  initial.provider,
  issuanceContext,
);
const issuanceBytes = await c2sp.c2spTlogEntryBytes(issuance, issuanceContext);

const chain = {
  sequence: 1,
  previousEventId: issuance.eventId,
  previousStateHash: c2sp.stateHash({
    fqdn: corpus.domain,
    status: 'ACTIVE',
    entity_thumb: entityThumb,
    operational_thumb: initialThumb,
  }),
};
const rotationEvent = {
  type: 'KEY_ROTATION',
  domain: corpus.domain,
  previousOperationalKid: initial.publicJwk.kid,
  previousOperationalThumbprint: initialThumb,
  newOperationalKid: rotated.publicJwk.kid,
  newOperationalAlg: rotated.publicJwk.alg,
  newOperationalThumbprint: rotatedThumb,
  newOperationalPublicKey: rotated.publicJwk,
  timestamp: new Date(corpus.events.rotation.timestamp * 1000),
};
const rotationContext = { previousOperationalKey: initial.publicJwk };
let rotation = c2sp.prepareC2spTlogEventForSigning(rotationEvent, corpus.lr, chain);
rotation = await c2sp.signPreparedC2spTlogEvent(
  rotation,
  'PreviousOperational',
  initial.provider,
  rotationContext,
);
rotation = await c2sp.signPreparedC2spTlogEvent(
  rotation,
  'NewOperational',
  rotated.provider,
  rotationContext,
);
const rotationBytes = await c2sp.c2spTlogEntryBytes(rotation, rotationContext);

const entries = {
  issuance: Buffer.from(issuanceBytes).toString('base64url'),
  rotation: Buffer.from(rotationBytes).toString('base64url'),
};

process.stdout.write(JSON.stringify({
  sdk: 'ts',
  entries,
  entitySignedIssuance,
}));
