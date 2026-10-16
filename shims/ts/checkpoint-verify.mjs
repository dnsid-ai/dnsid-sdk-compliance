// Signed sequences use the public reader or portable-bundle verifier, never a local reducer.
export async function verifyCheckpoint(caseData, c2sp, sdk) {
  if (!['scan', 'proof', 'missing'].includes(caseData.mode)
      || ![undefined, 'load', 'write', 'proof-fetch'].includes(caseData.fault)) {
    return { ok: false, error: 'AdapterError', message: 'unknown checkpoint mode/fault' };
  }
  const decode = value => new Uint8Array(Buffer.from(value, 'base64url'));
  const encode = value => Buffer.from(value).toString('base64url');
  let fault;
  let proofRequests = 0;
  const sentinel = new Error('injected checkpoint dependency failure');
  const storageFailure = () => {
    if (c2sp.C2spCheckpointStoreError) throw new c2sp.C2spCheckpointStoreError('injected store failure', sentinel);
    throw sentinel;
  };
  class Store extends c2sp.InMemoryTrustedC2spCheckpointStore {
    async load(...args) {
      if (fault === 'load') storageFailure();
      return super.load(...args);
    }
    async compareAndSwap(...args) {
      if (fault === 'write') storageFailure();
      return super.compareAndSwap(...args);
    }
  }
  const store = new Store();
  const proofSource = {
    async fetchConsistencyProof() {
      proofRequests++;
      if (fault === 'proof-fetch') {
        throw new c2sp.C2spTlogError('injected fetch failure', { transient: true, cause: sentinel });
      }
      return caseData.proof.map(decode);
    },
  };
  async function verify(evidence, mode = 'scan', scan = evidence.entries) {
    if (mode === 'proof' || mode === 'missing') {
      await c2sp.verifyC2spStreamBundle(new TextEncoder().encode(evidence.bundle), {
        expectedFqdn: caseData.domain, expectedLogReference: caseData.lr,
        policyBytes: new TextEncoder().encode(caseData.policy),
        bundleKeys: [c2sp.parseSignedNoteVerifierKey(caseData.bundleVerifierKey)],
        entityKey: caseData.entityJwk, maxBundleBytes: 128 * 1024, maxEvents: 16,
        maxBundleLifetimeMs: 300_000, checkpointFreshnessMs: 120_000,
        nowMs: caseData.now * 1000, trustedCheckpointStore: store,
        consistencyProofSource: mode === 'proof' ? proofSource : undefined,
      });
      return;
    }
    const reader = new c2sp.C2spTlogReader(caseData.lr, {
      policy: c2sp.parseC2spPolicyFile(caseData.policy), entityKey: caseData.entityJwk,
      trustedCheckpointStore: store,
      streamSource: {
        async load() {
          return {
            checkpoint: c2sp.parseCheckpoint(evidence.checkpoint), complete: true,
            entries: scan.map(item => ({ index: item.index, bytes: decode(item.entry) })),
          };
        },
      },
    });
    await reader.rebuildHistory(caseData.domain);
  }
  try {
    if (caseData.trusted) await verify(caseData.trusted);
  } catch (error) {
    return { ok: false, error: 'AdapterError', message: `trusted seed failed: ${error.message}` };
  }
  fault = caseData.fault;
  let result = { ok: true };
  try {
    await verify(caseData.candidate, caseData.mode, caseData.scanEntries);
  } catch (error) {
    const chain = [];
    for (let current = error; current && !chain.includes(current); current = current.cause) chain.push(current);
    const recognized = error instanceof sdk.VerificationError || chain.includes(sentinel);
    result = {
      ok: false, error: recognized ? 'CheckpointError' : 'AdapterError', message: error.message,
      errorCategory: error.errorCategory ?? null, transient: error.transient ?? null,
      causePreserved: chain.includes(sentinel),
    };
    for (const current of chain) {
      if (c2sp.MissingC2spConsistencyEvidenceError && current instanceof c2sp.MissingC2spConsistencyEvidenceError) {
        result.condition = 'consistency_unavailable';
      }
      if (c2sp.C2spCheckpointConsistencyError && current instanceof c2sp.C2spCheckpointConsistencyError) {
        result.diagnostics = {
          origin: current.origin, trustedTreeSize: current.trustedTreeSize, observedTreeSize: current.observedTreeSize,
          trustedRootHash: encode(current.trustedRootHash), observedRootHash: encode(current.observedRootHash),
        };
        // Diagnostic byte arrays must not expose mutable store state.
        current.trustedRootHash.fill(0);
        current.observedRootHash.fill(0);
      }
    }
  }
  fault = undefined;
  const stored = await store.load(c2sp.parseC2spTlogLr(caseData.lr).origin);
  result.stored = stored ? {
    origin: stored.origin, treeSize: stored.treeSize, rootHash: encode(stored.rootHash),
    witnessTime: stored.witnessTime.getTime() / 1000,
  } : null;
  result.proofRequests = proofRequests;
  result.proofRequested = proofRequests > 0;
  return result;
}
