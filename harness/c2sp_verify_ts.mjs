import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const sdkDir = process.env.DNSID_TS_DIR;
if (!sdkDir) throw new Error('DNSID_TS_DIR is not set');
if (process.argv.length !== 3) throw new Error('usage: c2sp_verify_ts.mjs VECTOR');

const sdk = await import(pathToFileURL(join(
  sdkDir,
  'packages/log-c2sp-tlog/dist/index.js',
)).href);
const vector = JSON.parse(await readFile(process.argv[2], 'utf8'));
const trust = vector.trust;
const bundle = JSON.parse(vector.bundle);
const verified = await sdk.verifyC2spStreamBundle(
  new TextEncoder().encode(vector.bundle),
  {
    expectedFqdn: bundle.fqdn,
    expectedLogReference: bundle.lr,
    policyBytes: new TextEncoder().encode(vector.policy),
    bundleKeys: [sdk.parseSignedNoteVerifierKey(trust.bundle_verifier_key)],
    entityKey: trust.entity_jwk,
    maxBundleBytes: 128 * 1024,
    maxEvents: 16,
    maxBundleLifetimeMs: trust.max_bundle_lifetime_ms,
    checkpointFreshnessMs: trust.checkpoint_freshness_ms,
    nowMs: trust.now * 1000,
    trustedCheckpointStore: new sdk.InMemoryTrustedC2spCheckpointStore(),
  },
);

process.stdout.write(JSON.stringify({
  sdk: 'ts',
  eventCount: verified.events.length,
  status: verified.bundle.state.loggedState,
  activeOperationalThumbprint: verified.activeOperationalKeyThumbprint,
  bundleSignerKid: verified.bundle.signature.kid,
}));
