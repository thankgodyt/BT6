### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Weight Boosts, Corrupting Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the universal `BlockSupportsPeras` instance is a stub that unconditionally accepts every inbound `PerasCert` as valid, performing no cryptographic or structural checks. Because this function is the sole validation gate between a peer-supplied certificate and the `PerasCertDB`/chain-selection pipeline, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block — including one on a non-canonical fork — causing the victim node to prefer that fork over the honest chain.

---

### Finding Description

**Root cause — always-`Right` stub:** [1](#0-0) 

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

The function signature promises `Either (PerasValidationErr blk) (ValidatedPerasCert blk)`, but the body is a constant `Right` — no signature check, no committee-membership check, no round-validity check, and no verification that `pcCertBoostedBlock` refers to a real or eligible block.

**Entry path — peer-facing miniprotocol:**

The `PerasCertDiffusion` miniprotocol handler wires directly to this stub: [2](#0-1) 

The inbound handler calls `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function: [3](#0-2) 

`processCerts` partitions results into valid/invalid; since `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain-selection effect:**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it: the certificate is stored in `PerasCertDB`, and if the boosted block is in the VolatileDB, chain selection is immediately re-triggered for that block: [5](#0-4) 

The `PerasCertDB` implementation builds a `PerasWeightSnapshot` from all stored certificates, keyed by `pcCertBoostedBlock`: [6](#0-5) 

Chain selection then compares candidates by `wsvTotalWeight = blockNo + weightBoost`, so a fork whose tip block has been boosted by an injected certificate can overtake the honest chain: [7](#0-6) 

**Analog to the original report:**

In `tokenToXtz`, tokens are sent to the user-controlled `to` field instead of the contract. Here, the user-controlled `pcCertBoostedBlock` field inside the peer-supplied `PerasCert` is accepted without validation and used directly to assign weight in chain selection — the attacker controls the "destination" (which block gets boosted) just as the Dexter attacker controlled the token recipient.

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker with a single peer connection can:
1. Send a `PerasCert` with `pcCertBoostedBlock` pointing to the tip of a minority fork.
2. The victim node adds the certificate to `PerasCertDB` without any check.
3. The boosted fork's `wsvTotalWeight` exceeds the honest chain's weight.
4. The victim node switches to the minority fork, diverging from the canonical chain.

Because `PerasCertDB` deduplicates by round number, one certificate per round can be injected. With `perasWeight` configured to a large value, a single injected certificate can outweigh many honest blocks, making the attack effective even against a well-connected node.

---

### Likelihood Explanation

**Likelihood: High** — when Peras is enabled (the feature flag activates the `PerasCertDiffusion` miniprotocol). The attacker requires only a standard peer connection; no keys, stake, or privileged access are needed. The stub is the active production code path for all block types via the universal `instance StandardHash blk => BlockSupportsPeras blk`. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete implementation shipped in the current codebase.

---

### Recommendation

**Short term:** Replace the stub with a real implementation that verifies:
- The certificate's aggregate BLS signature against the committee's aggregate verification key.
- That the signers form a quorum of the voting committee for the given round.
- That `pcCertBoostedBlock` refers to a block that was a valid candidate in the corresponding Peras round.

Until real validation is implemented, the `PerasCertDiffusion` miniprotocol should be disabled or the inbound handler should reject all externally received certificates.

**Long term:** Add property-based tests (QuickCheck/Hedgehog) that verify `validatePerasCert` rejects certificates with invalid signatures, wrong committee membership, and arbitrary boosted-block hashes, analogous to the existing `prop_fakeVotesDontVerify` tests for the WFALS committee.

---

### Proof of Concept

1. Connect a malicious peer to a Peras-enabled node.
2. Identify a block `B` on a minority fork in the victim's VolatileDB (slot/hash known from ChainSync).
3. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B }` for any round `r` not yet in the victim's `PerasCertDB`.
4. Send the certificate via the `PerasCertDiffusion` miniprotocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
6. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
7. `chainSelSync` finds `B` in the VolatileDB, triggers `chainSelectionForBlock` for `B`.
8. The fork containing `B` now has `wsvTotalWeight = blockNo(B) + perasWeight`, which exceeds the honest chain's `blockNo(tip)` if `perasWeight` is large enough.
9. The victim node switches to the minority fork.

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
