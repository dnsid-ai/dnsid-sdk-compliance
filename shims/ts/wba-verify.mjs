// Executes native WBA verification with real TLS and the SDK's address guard.
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const fixtures = new URL('../testdata/', import.meta.url);

export async function verifyWba(req, sdk, wba, sdkDir) {
  const { createSsrfSafeFetch } = await import(pathToFileURL(join(sdkDir, 'packages/transport/dist/index.js')).href);
  const { ArgumentError, DNSSECState, DnsIdTxtRecord, JWKS, NoopLogReader, VerificationCode, VerificationError, VerifiedDomain, jwkThumbprint } = sdk;
  const s = req.verification;
  const domain = s.signerDomain;
  const publicKey = { kty: 'OKP', crv: 'Ed25519', x: req.key.x };
  let clock = s.now;
  let discoveries = 0;
  let phase = 0;
  const seen = new Set();
  const replayFailure = new Error('fixture replay store unavailable');
  const originalNow = Date.now;
  const originalLookup = dns.lookup;
  const originalConnect = tls.connect;
  const server = createServer({
    cert: readFileSync(new URL('wba-cert.pem', fixtures)),
    key: readFileSync(new URL('wba-key.pem', fixtures)),
  }, (_request, response) => {
    discoveries++;
    clock = s.finishedAt;
    response.setHeader('Connection', 'close');
    if (s.directoryTimeout) return;
    if (s.redirects.length) {
      response.writeHead(302, { Location: s.redirects[0].url });
      response.end();
      return;
    }
    response.writeHead(s.directoryStatus ?? req.directory.status, req.directory.headers);
    response.end(Buffer.from(req.directory.bodyBase64, 'base64'));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  try {
    Date.now = () => clock * 1000;
    dns.lookup = async () => {
      const addresses = discoveries && s.redirects.length ? s.redirects[0].resolvedAddresses : s.resolvedAddresses;
      return addresses.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
    };
    tls.connect = (options, ...args) => {
      const lookup = options.lookup;
      return originalConnect({ ...options, port: server.address().port,
        lookup(host, opts, callback) {
          // The SDK checks DNS answers before mapping the physical dial.
          lookup(host, opts, (error, address) => {
            if (error) callback(error, '', 0);
            else if (Array.isArray(address)) callback(null, [{ address: '127.0.0.1', family: 4 }]);
            else callback(null, '127.0.0.1', 4);
          });
        },
      }, ...args);
    };
    syncBuiltinESMExports();
    const resolver = {
      async verifyDomain(signer, peerCert) {
        // Identity evidence is injected at the public resolver boundary.
        if (!s.dnsidExists) throw new VerificationError('fixture DNSid record absent', { code: VerificationCode.RecordInvalid });
        if (!s.acceptanceAllowed && phase) throw new VerificationError('fixture acceptance denied', { code: VerificationCode.CounterpartyNotAccepted });
        if (s.requiresMtls && !peerCert) throw new VerificationError('fixture current mTLS peer missing', { code: VerificationCode.TLSError });
        const now = new Date(Date.now());
        const keys = (phase ? s.currentKu : [publicKey]).map(key => ({ alg: 'EdDSA', kid: 'fixture-ku', ...key }));
        const record = new DnsIdTxtRecord();
        record.v = 'dnsid-draft-01';
        return new VerifiedDomain({
          domain: signer, record, jwks: new JWKS(keys), signingKey: publicKey,
          signingKeyThumbprint: await jwkThumbprint(publicKey),
          tlsCert: { san: [domain], notAfter: new Date((clock + 3600) * 1000) },
          registryStatus: { state: 'ACTIVE', lastTransitionAt: now },
          verifiedAt: now, dnsTTL: s.dnsTTL ?? 300, keyBoundAt: now,
          lastStatusCheckAt: now, dnssecState: DNSSECState.UNKNOWN,
          logReader: new NoopLogReader('fixture'),
        });
      },
    };
    const transport = createSsrfSafeFetch(s.directoryTlsValid ? { caBundlePath: new URL('wba-cert.pem', fixtures).pathname } : {}, { decompress: false });
    const config = { clockSkew: s.clockSkew };
    // Buffer the fixed fixture bytes before exposing them to the verifier;
    // Node's Readable.toWeb bridge can race cancellation on an early rejection.
    const discoveryFetch = async request => {
      const response = await transport(request);
      return new Response(await response.arrayBuffer(), { status: response.status, headers: response.headers });
    };
    const verifier = new wba.WebBotAuthProfile({ identityResolver: resolver, discoveryFetch, webBotAuth: config });
    Object.assign(config, s.configMutation ?? {});
    const opts = {
      signerDomain: domain, discovery: { uri: s.trustedDiscoveryUri, type: 'directory' },
      requiredComponents: s.requiredComponents,
      timeoutMs: s.timeoutMs,
      consumeNonce: s.replayEnabled ? async ({ signerDomain, keyid, nonce }) => {
        if (!s.replayStoreAvailable) throw replayFailure;
        const key = JSON.stringify([signerDomain, keyid, nonce]);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      } : undefined,
    };
    const message = () => new Request(req.request.url, {
      method: req.request.method, headers: req.request.headers,
      body: req.request.bodyBase64 == null ? undefined : Buffer.from(req.request.bodyBase64, 'base64'),
    });
    if (s.cacheHit || s.nonceSeen) {
      try { await verifier.verifyWebBotAuthSignedRequest(message(), opts); }
      catch (error) { return { ok: false, error: 'AdapterError', message: `warm-up failed: ${error}` }; }
    }
    phase = 1;
    clock = s.now;
    const verified = await verifier.verifyWebBotAuthSignedRequest(message(), opts);
    return { ok: true, signerDomain: verified.domain, discoveryRequests: discoveries };
  } catch (error) {
    if (error instanceof VerificationError) return { ok: false, error: 'ConformanceError', nativeError: error.name, code: error.code, transient: error.transient, message: error.message, discoveryRequests: discoveries };
    if (error === replayFailure) return { ok: false, error: 'ConformanceError', nativeError: error.name, message: error.message, discoveryRequests: discoveries };
    if (error instanceof ArgumentError) return { ok: false, error: 'ArgumentError', message: error.message, discoveryRequests: discoveries };
    return { ok: false, error: 'AdapterError', message: String(error?.stack ?? error) };
  } finally {
    Date.now = originalNow;
    dns.lookup = originalLookup;
    tls.connect = originalConnect;
    syncBuiltinESMExports();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
