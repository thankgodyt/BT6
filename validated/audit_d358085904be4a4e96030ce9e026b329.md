### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Manipulate Chain Selection Weight - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate ingest path uses a stub `validatePerasCert` implementation that unconditionally returns `Right` for every certificate received from any peer. Because no cryptographic or quorum check is performed, an unprivileged peer can send a crafted `PerasCert` pointing to any block in the VolatileDB, causing the node to apply a weight boost of `PerasWeight 15` to that block's chain and potentially switch to a non-canonical fork.

---

### Finding Description

**Stub validator always accepts**

The degenerate `BlockSupportsPeras` instance in `SupportsPeras.hs` carries an explicit TODO and returns `Right` for every certificate without performing any cryptographic or quorum check:

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

**Production ingest path wires the stub directly**

`makePerasCertPoolWriterFromChainDB` — the function used in production to process inbound peer certificates — passes this stub as the validator, with a matching TODO:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate; if all return `Right` (which they always do), every certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Chain selection is triggered for the boosted block**

`chainSelSync` processes the accepted certificate. If the boosted block is not on the current chain and is present in the VolatileDB, it immediately triggers `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Weight boost is applied during comparison**

`WeightedSelectView.preferCandidate` computes `wsvTotalWeight = unBlockNo(blockNo) + wsvWeightBoost`. A chain carrying the boosted block gains `PerasWeight 15` (the hardcoded default in `mkPerasParams`):

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
``` [5](#0-4) 

`perasWeight` is fixed at `PerasWeight 15` in `mkPerasParams`: [6](#0-5) 

---

### Impact Explanation

An adversarial peer can send a `PerasCert` whose `pcCertBoostedBlock` points to any block already in the victim node's VolatileDB (e.g., a block on a minority fork). The certificate passes validation unconditionally. Chain selection is re-run with the minority fork's chain receiving `+15` total weight. Because `wsvTotalWeight = blockNo + weightBoost`, a fork that is up to 15 blocks shorter than the current selection becomes preferred. The node rolls back to the fork and adopts it as its canonical chain — a chain-selection safety failure caused by a single unauthenticated peer message.

This matches the **High** impact category: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

- The ObjectDiffusion miniprotocol for Peras certificates is reachable by any connected peer (no authentication or privilege required).
- The attacker only needs to know the hash of a block already in the victim's VolatileDB (observable via ChainSync).
- No stake, key material, or operator access is required.
- The stub validator is wired into the production `makePerasCertPoolWriterFromChainDB` path, not just tests.

---

### Recommendation

1. **Do not wire the stub validator into the production ingest path.** Until real cryptographic and quorum validation is implemented, the `makePerasCertPoolWriterFromChainDB` function should refuse all inbound certificates (return an error or no-op) rather than accept them unconditionally.
2. **Implement `validatePerasCert` with actual BLS aggregate signature verification and quorum-stake threshold checks** before enabling the Peras certificate diffusion path on any network that uses Peras weight boosts for chain selection.
3. **Add a guard in `processCerts`** that rejects any certificate whose `pcCertBoostedBlock` slot is not within the expected Peras round window, as a defense-in-depth measure even after real validation is added.

---

### Proof of Concept

1. Attacker connects to a victim node as a normal peer.
2. Via ChainSync, attacker learns hash `H` of a block on a minority fork at block number `N-14` (14 blocks behind the current tip at `N`).
3. Attacker sends a single `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint s H }` via the ObjectDiffusion miniprotocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
5. `ChainDB.addPerasCertAsync` is called; `chainSelSync` finds block `H` in the VolatileDB and calls `chainSelectionForBlock`.
6. `preferAnchoredCandidate` computes: minority fork total weight = `(N-14) + 15 = N+1 > N` (honest chain). `ShouldSwitch` is returned.
7. The node rolls back 14 blocks and adopts the minority fork as its canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
