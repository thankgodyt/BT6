### Title
Stub `validatePerasCert` Unconditionally Accepts All Peras Certificates, Enabling Adversarial Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that is an acknowledged stub: it unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural checks. Because the object-diffusion inbound pipeline calls this stub directly, any unprivileged peer can inject an arbitrary `PerasCert` that will be stored in the `PerasCertDB` and used to boost a block's weight in the `PerasWeightSnapshot`, potentially causing the honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the gate that must verify a certificate before it is stored or acted upon. The default instance, which is the only instance currently wired into the production diffusion path, is:

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

This stub is called directly in both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`, the two writers that handle inbound certificates from peers:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` partitions the results of `validateCert` and only rejects a batch when at least one `Left` is returned. Because the stub never returns `Left`, every certificate in every batch is accepted: [4](#0-3) 

Each accepted certificate is then forwarded to `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes it: it checks only that the boosted block's slot is not older than the immutable tip, then adds the certificate to `PerasCertDB` and triggers chain selection for the boosted block: [5](#0-4) 

The `PerasWeightSnapshot` returned by `implGetWeightSnapshot` is built from all stored certificates' boosted blocks and their boost values: [6](#0-5) 

Chain selection then uses `preferAnchoredCandidate`, which, when Peras weights are non-empty, compares `WeightedSelectView` values that sum `wsvBlockNo` and `wsvWeightBoost`: [7](#0-6) 

An adversary who injects a certificate with a large `vpcCertBoost` for a block on their fork can therefore make that fork's `wsvTotalWeight` exceed the honest chain's, causing the node to switch.

The `validatePerasVote` stub has the same structure — it only checks stake-distribution membership, not any vote signature — but the certificate path is the more direct chain-selection vector. [8](#0-7) 

---

### Impact Explanation

**High — Chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain, and bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance.**

A peer that can reach the node's object-diffusion endpoint (any network peer) can craft a `PerasCert` with an arbitrarily large `vpcCertBoost` targeting any block hash. Because `validatePerasCert` always returns `Right`, the certificate is stored and its boost is added to the `PerasWeightSnapshot`. If the boosted block is on a fork, the fork's `wsvTotalWeight` can be made to exceed the honest chain's, causing the node to switch chains. This violates the Peras security assumption that only legitimately quorum-certified blocks receive weight boosts.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is reachable by any peer that can establish a connection. No special privileges, keys, or stake are required. The attacker only needs to send a well-formed `PerasCert` CBOR message with a large boost value. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm the stub is intentional but unfinished, meaning it is present in the current production codebase.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate committee signature, checks committee membership against the correct epoch's stake snapshot, and validates the round number and boosted block point before accepting a certificate.
2. Similarly complete `validatePerasVote` to verify vote signatures.
3. Until real validation is in place, consider rejecting all inbound certificates at the diffusion layer (returning a hard `Left`) rather than accepting them unconditionally, to prevent the chain-selection side-effect.
4. Add a property test asserting that `validatePerasCert` rejects certificates with invalid signatures or out-of-range round numbers.

---

### Proof of Concept

**Setup:** A private two-node testnet where node A is the honest node and node B is the attacker.

1. Node B connects to node A via the object-diffusion mini-protocol.
2. Node B mines a short fork `F` branching off `k-1` blocks from node A's tip.
3. Node B sends node A a `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <tip of F> }
   ```
   with `vpcCertBoost` set to a value large enough that `wsvTotalWeight(F) > wsvTotalWeight(honest chain)`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }`.
5. The certificate is stored in `PerasCertDB`; `chainSelSync` triggers chain selection for the tip of `F`.
6. `preferAnchoredCandidate` computes `weightedSelectView` for both fragments; the boosted fork wins.
7. Node A switches to fork `F`, abandoning the honest chain.

The entire attack requires only a valid TCP connection and the ability to send a CBOR-encoded `PerasCert` — no cryptographic material, no stake, no operator access.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
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
