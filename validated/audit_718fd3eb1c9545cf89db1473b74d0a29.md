### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is an intentional stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural checks. Because this function is the sole validation gate in the live network ingest path (`processCerts` → `ChainDB.addPerasCertAsync`), any unprivileged peer can inject an arbitrary Peras certificate for any round and any block point. The accepted certificate immediately contributes its `perasWeight` boost to chain selection, allowing an attacker to steer an honest node toward a non-canonical chain without holding any stake or keys.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote validation. Its only production instance (the `StandardHash blk` catch-all) contains the following stub:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

The TODO comment explicitly acknowledges that no validation is performed. The function wraps the raw, unverified `PerasCert` directly into a `ValidatedPerasCert` and assigns it the full configured `perasWeight` boost.

This stub is wired directly into the live network ingest path. `makePerasCertPoolWriterFromChainDB` (the production writer used with the `ChainDB`) calls `processCerts` with `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass (which they always do), forwards them to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Once stored, `implGetWeightSnapshot` in `PerasCertDB.Impl` reads every stored `ValidatedPerasCert` and feeds its `getPerasCertBoost` value into `mkPerasWeightSnapshot`, which is then consumed by chain selection in `ChainSel.hs`: [4](#0-3) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A crafted certificate for an attacker-chosen `(roundNo, blockPoint)` pair is accepted without any check on:
- BLS aggregate signature validity
- Committee membership or VRF eligibility of the signers
- Whether the claimed quorum stake threshold was actually met
- Whether the boosted block even exists on any known chain

The accepted certificate immediately adds `perasWeight` to the attacker-chosen block in the weight snapshot used by chain selection. Because Peras weight is additive on top of chain length, a sufficiently large `perasWeight` parameter can cause the node to switch to a shorter chain that carries the fraudulent boost, constituting a chain-selection safety failure driven entirely by a peer-supplied network message.

---

### Likelihood Explanation

**High.** The ObjectDiffusion miniprotocol is a standard peer-to-peer channel reachable by any node on the network. No stake, keys, or privileged access are required. The attacker only needs to connect as a peer and send a well-formed (but cryptographically unverified) `PerasCert` message. The stub is the universal production instance — there is no other `BlockSupportsPeras` instance that would override it for Cardano blocks in this codebase.

---

### Recommendation

1. Implement real validation inside `validatePerasCert` before any deployment of Peras on a live network. At minimum this must verify: the BLS aggregate signature over `(roundNo, boostedBlock)`, that the aggregate verification key was correctly assembled from eligible committee members, and that the claimed stake meets the quorum threshold.
2. Until real validation is in place, gate the ObjectDiffusion cert-ingest path behind a feature flag so that no peer-supplied certificates are accepted on production nodes.
3. Track the linked issue (`cardano-peras/issues/120`) as a security-critical blocker, not merely a correctness improvement. [5](#0-4) 

---

### Proof of Concept

**Private-testnet reproduction sequence:**

1. Start two nodes A (honest) and B (attacker) connected via the ObjectDiffusion miniprotocol.
2. On node B, construct a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on a minority fork (or a non-existent block).
3. Send the certificate to node A via the cert-diffusion channel.
4. `processCerts` on node A calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert perasWeight)` unconditionally.
5. The certificate is stored in `PerasCertDB` and its boost is included in the next `implGetWeightSnapshot` call.
6. Chain selection in `ChainSel.hs` now sees the attacker-chosen block carrying an extra `perasWeight` boost and, if that weight exceeds the honest chain's advantage, switches to the attacker's fork.

No BLS keys, no stake, no operator access required — only a peer connection and a serialized `PerasCert` value. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```
