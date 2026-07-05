### Title
`validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates Without Cryptographic Verification, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which applies to **all** block types, implements `validatePerasCert` as an unconditional `Right` — accepting every inbound certificate without any cryptographic check. This instance is the live production code path wired into the `PerasCertDiffusion` mini-protocol handler. An unprivileged peer can send a crafted `PerasCert` that names any block in the VolatileDB as its boosted target; the certificate will pass "validation" and be stored, triggering chain selection that inflates the weight of the attacker-chosen chain fragment.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must verify a certificate's cryptographic integrity (committee membership, aggregate BLS signature, quorum threshold, round validity) before the certificate is admitted to the `PerasCertDB` and used in chain selection.

The only concrete instance in the codebase is the blanket degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

Every field of the inbound `PerasCert` — the round number, the boosted block point, and implicitly any aggregate signature — is accepted verbatim. No committee membership check, no BLS aggregate signature verification, no quorum threshold check, and no round-validity check is performed.

This stub is wired directly into the production network handler. `makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on every new certificate; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is instantiated in the node-to-node handler at:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

Once the certificate reaches `ChainDB.addPerasCertAsync`, `chainSelSync` processes it: it adds the certificate to the `PerasCertDB` and, if the boosted block is in the VolatileDB, immediately triggers `chainSelectionForBlock` for that block: [5](#0-4) 

Chain selection then uses `WeightedSelectView`, which adds `vpcCertBoost` (set to `perasWeight params` from the degenerate instance) to the total weight of any fragment containing the boosted block: [6](#0-5) 

---

### Impact Explanation

**Impact class: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

When Peras is enabled, an attacker peer can:

1. Observe which block hash is present in the target node's VolatileDB (via ChainSync headers).
2. Craft a `PerasCert` naming that block as `pcCertBoostedBlock` with an arbitrary `pcCertRound`.
3. Send it over the `PerasCertDiffusion` mini-protocol.
4. The certificate passes `validatePerasCert` unconditionally, is stored, and triggers chain selection.
5. The attacker-chosen chain fragment now carries `perasWeight params` additional weight.

If the attacker targets a block on a minority fork, the honest node may switch to that fork, diverging from the canonical chain. Because the boost is permanent in the `PerasCertDB` for that round, the effect persists across subsequent chain selection rounds. Multiple crafted certificates for different rounds can compound the artificial weight, making the attack progressively easier to sustain.

---

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is a standard node-to-node protocol; any peer that can establish a connection can send certificates. The `PerasCert` wire type contains only a round number and a block point — both trivially constructable. No key material, stake, or committee membership is required. The only prerequisite is that Peras is enabled (not the default today, but the intended production configuration). The attack requires no operator compromise, no key leakage, and no majority stake.

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that:

1. Verifies the aggregate BLS signature against the claimed committee members (using the `WFALS` or `EveryoneVotes` committee scheme as appropriate).
2. Checks that the signers collectively hold stake above the quorum threshold.
3. Validates that each signer is an eligible committee member for the claimed round (VRF eligibility for non-persistent members).
4. Validates the round number against the current epoch's Peras schedule.

Until the full implementation is ready, the `processCerts` inbound handler should refuse all certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the network handler is safe-by-default when Peras plumbing is incomplete. The existing TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this work.

---

### Proof of Concept

**Entry point:** `PerasCertDiffusion` inbound mini-protocol, reachable from any node-to-node peer.

**Crafted input:**
```haskell
PerasCert
  { pcCertRound     = PerasRoundNo 42          -- any round not yet in DB
  , pcCertBoostedBlock = blockPoint targetBlock -- any block in peer's VolatileDB
  }
```

**Execution trace:**

1. Peer sends the above `PerasCert` via `ObjectDiffusion`.
2. `objectDiffusionInbound` collects it and calls `opwAddObjects [cert]`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. Degenerate instance returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight params}` — **no checks performed**.
5. `addCert (WithArrivalTime now validatedCert)` → `ChainDB.addPerasCertAsync chainDB`.
6. `chainSelSync` adds cert to `PerasCertDB`, finds `targetBlock` in VolatileDB, calls `chainSelectionForBlock`.
7. `weightBoostOfFragment` now returns `perasWeight params` for any fragment containing `targetBlock`.
8. `WeightedSelectView.preferCandidate` may now prefer the fragment containing `targetBlock` over the previously preferred chain. [7](#0-6) [8](#0-7) [3](#0-2) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
