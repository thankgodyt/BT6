### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Unprivileged Chain-Selection Manipulation via Peras Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance — used for all block types in the current codebase — implements `validatePerasCert` as a stub that unconditionally returns `Right`, accepting every inbound Peras certificate as valid regardless of its content. Because the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`) passes this stub as the validation function, any unprivileged peer can inject crafted `PerasCert` values that boost arbitrary blocks in the VolatileDB. The injected boosts are stored in the `PerasCertDB`, propagate into the `PerasWeightSnapshot` used by chain selection, and can cause an honest node to prefer a non-canonical or adversarially-controlled fork over the honest chain.

---

### Finding Description

**Root cause — stub validation always returns `Right`:**

The `BlockSupportsPeras` class has a degenerate default instance (explicitly marked "TODO: degenerate instance for all blks to get things to compile") that overrides `validatePerasCert` with:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params  -- always PerasWeight 15
      }
``` [1](#0-0) 

This instance is the only one in scope for all block types.

**Production inbound path uses the stub:**

`makePerasCertPoolWriterFromChainDB` — the production writer for peer-received certificates — passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls this function on every inbound cert. Since the stub always returns `Right`, every cert passes: [3](#0-2) 

**Accepted certs enter the ChainDB and trigger chain selection:**

After passing validation, each cert is forwarded to `ChainDB.addPerasCertAsync`. Inside `chainSelSync`, the `ChainSelAddPerasCert` branch adds the cert to `cdbPerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

**Weight snapshot is built directly from all stored certs:**

`implGetWeightSnapshot` computes the `PerasWeightSnapshot` by iterating over every cert in `pcdsCertsByTicket`, including attacker-injected ones: [5](#0-4) 

**Chain selection consults the weight snapshot:**

`chainSelectionForBlock` reads the current `PerasWeightSnapshot` via `Query.getPerasWeightSnapshot` and passes it to `preferAnchoredCandidate` / `compareChainDiffs`. A chain whose blocks have accumulated boost weight is preferred over a longer honest chain: [6](#0-5) 

**Attack flow:**

1. Attacker connects as an ordinary peer.
2. Attacker sends N crafted `PerasCert` objects via the object-diffusion mini-protocol, each with a distinct `pcCertRound` and `pcCertBoostedBlock` pointing to blocks on an adversarial fork.
3. Each cert passes `validatePerasCert` (always `Right`) and is stored in the `PerasCertDB`.
4. Each cert triggers `chainSelectionForBlock` for the boosted block.
5. The `PerasWeightSnapshot` now assigns `N × 15` additional weight to the adversarial fork.
6. `preferAnchoredCandidate` selects the adversarial fork over the honest chain if the honest chain is not more than `N × 15` blocks longer.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

The Peras weight boost of 15 per certificate means a single attacker-controlled peer can, by sending N distinct round-numbered certificates, cause the victim node to prefer a fork that is up to `N × 15` blocks shorter than the honest chain. Because there is no cap on how many distinct round numbers an attacker can use, the attacker can accumulate an arbitrarily large weight advantage on any fork present in the VolatileDB. This directly violates the chain-selection security invariant: an honest node should only switch to a chain that is genuinely heavier under the Peras rules, not one made artificially heavier by unauthenticated peer-supplied certificates.

---

### Likelihood Explanation

**High.** The entry point is the standard object-diffusion mini-protocol, reachable by any peer without any credentials. The stub is the only `validatePerasCert` implementation in the codebase and is used in both the `PerasCertDB`-direct writer and the production `ChainDB` writer. No additional preconditions are required beyond establishing a peer connection.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's aggregate BLS/committee signature against the registered voting committee for the claimed round.
- That the claimed `pcCertBoostedBlock` is a real block hash known to the ledger.
- That the quorum stake threshold is met by the signers.

Until the real implementation is in place, the inbound certificate pipeline should reject all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them. The TODO comment at line 103 and 125–126 of `PerasCert.hs` and lines 350–358 of `SupportsPeras.hs` should be treated as a security-critical blocker, not a deferred cleanup item.

---

### Proof of Concept

**Setup:** A private Cardano testnet with at least two nodes, A (victim) and B (attacker peer).

1. Node B connects to node A via the standard peer-to-peer diffusion layer.
2. Node B constructs a series of `PerasCert` values:
   ```
   cert_i = PerasCert { pcCertRound = i, pcCertBoostedBlock = <hash of block on adversarial fork> }
   ```
   for i = 1 … N, all pointing to blocks on a shorter adversarial fork F that diverges from the honest chain.
3. Node B sends these certs to node A via the object-diffusion mini-protocol.
4. On node A, `processCerts` calls `validatePerasCert mkPerasParams` on each cert; all return `Right`.
5. Each cert is stored in `cdbPerasCertDB` and triggers `chainSelectionForBlock` for the boosted block.
6. `implGetWeightSnapshot` returns a snapshot assigning weight `N × 15` to blocks on fork F.
7. `preferAnchoredCandidate` now prefers fork F over the honest chain if the honest chain's length advantage is less than `N × 15` blocks.
8. Node A switches to fork F — a non-canonical chain — without any legitimate Peras quorum having been formed.

**Expected (correct) outcome:** All N certificates are rejected because no real committee signature is present.
**Actual outcome:** All N certificates are accepted; node A's chain selection is manipulated.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-531)
```haskell
    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
