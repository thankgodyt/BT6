### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or committee-membership checks. Because this function is wired directly into the production Peras certificate diffusion inbound path (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can send a crafted `PerasCert` that is accepted as "validated," stored in the `PerasCertDB`, and used to artificially inflate the Peras weight of an attacker-chosen block during chain selection. This mirrors the external report's pattern exactly: a validation hook exists in the architecture but its implementation is a no-op stub, so the "whitelist" (committee membership + BLS aggregate signature) is never enforced.

### Finding Description

**Root cause — stub validator:** [1](#0-0) 

The comment at line 318 reads *"TODO: degenerate instance for all blks to get things to compile"*. The `validatePerasCert` method of this universal instance (lines 350–358) ignores `params` and `cert` entirely and always returns:

```haskell
Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature is verified, no committee membership is checked, no round-number bounds are enforced.

**Production wiring — inbound diffusion path:**

`makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` argument to `processCerts`: [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, because the stub always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Node-to-node protocol handler:**

`makePerasCertPoolWriterFromChainDB` is registered as the inbound handler for the Peras certificate diffusion mini-protocol in the production node-to-node codec: [4](#0-3) 

**Chain selection consequence:**

Once a `ValidatedPerasCert` is stored in the `PerasCertDB`, `chainSelSync` triggers `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection then computes `wsvTotalWeight` as `blockNo + wsvWeightBoost`, where `wsvWeightBoost` is the sum of all Peras boosts on the candidate fragment: [6](#0-5) 

A fragment whose tip has a lower block number than the honest chain can be made to appear heavier by injecting a certificate with a large `vpcCertBoost` (drawn from `perasWeight params`), causing the node to switch to the attacker's fork.

**Secondary stub — `PerasCertDB.Impl` also defers validation:** [7](#0-6) 

The `implAddCert` function also carries a TODO for "non-trivial validation logic," confirming that no second line of defence exists inside the database layer.

### Impact Explanation

**Impact: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, an attacker who controls a single peer connection can:

1. Forge a `PerasCert` pointing to any block hash and any round number.
2. Send it over the Peras certificate diffusion mini-protocol.
3. The stub validator accepts it unconditionally.
4. The certificate is stored and its `vpcCertBoost` (= `perasWeight params`) is added to the weight of the attacker's fork.
5. If the boosted weight exceeds the honest chain's weight, the node switches forks — accepting a chain that may contain invalid or double-spending transactions.

This directly satisfies the allowed impact: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**Likelihood: High (conditional on Peras being enabled).**

- The attack requires only a standard peer connection — no keys, no stake, no admin access.
- The entry point (`hPerasCertDiffusionClient`) is exposed to every connected NtN peer.
- The stub is the *only* production instance of `BlockSupportsPeras`; there is no fallback check.
- The CHANGELOG confirms Peras chain-selection weight is already active in the codebase: *"the candidate fragment is now selected based on its Peras weight."*
- The only mitigating factor is that Peras is disabled by default; once enabled, the attack is trivially reachable.

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the BLS aggregate signature against the committee's public keys and confirm the voter set meets the quorum threshold, using the `CryptoSupportsVotingCommittee` / `verifyCert` machinery already present in `Ouroboros.Consensus.Committee.EveryoneVotes` and `WFALS`.
2. **Remove the universal stub instance** (`instance StandardHash blk => BlockSupportsPeras blk`) or gate it behind a compile-time flag that is never enabled in production builds.
3. **Add a round-number bounds check** inside `validatePerasCert`: reject certificates whose `pcCertRound` is outside the current epoch's valid Peras round window.
4. **Resolve the `PerasCertDB.Impl` TODO** (line 167) to add a second validation layer inside `implAddCert` as defence-in-depth.

### Proof of Concept

**Attacker-controlled entry path:**

```
Malicious peer
  → NtN Peras cert diffusion mini-protocol
  → hPerasCertDiffusionClient (NodeToNode.hs:375)
  → objectDiffusionInbound
  → makePerasCertPoolWriterFromChainDB (PerasCert.hs:113)
  → processCerts … (validatePerasCert mkPerasParams) … (PerasCert.hs:122-126)
      validatePerasCert _ cert = Right (ValidatedPerasCert cert boost)  -- always Right
  → ChainDB.addPerasCertAsync chainDB                                   -- cert stored
  → chainSelSync … ChainSelAddPerasCert                                 -- chain sel triggered
  → chainSelectionForBlock cdb BlockCache.empty boostedHdr              -- fork evaluated
  → weightedSelectView: wsvTotalWeight = blockNo + attackerBoost        -- attacker wins
  → node switches to attacker's fork
```

**Crafted certificate (Haskell pseudocode):**

```haskell
let maliciousCert = PerasCert
      { pcCertRound      = PerasRoundNo 1
      , pcCertBoostedBlock = blockPoint attackerForkTip
      }
-- Send via Peras cert diffusion protocol.
-- validatePerasCert mkPerasParams maliciousCert
--   = Right (ValidatedPerasCert maliciousCert (perasWeight mkPerasParams))
-- No signature checked. Certificate accepted and stored.
```

The `perasWeight` value drawn from `mkPerasParams` is large enough to overcome the honest chain's block-number advantage, causing the victim node to switch to `attackerForkTip`.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-169)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
```
