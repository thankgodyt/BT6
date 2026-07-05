### Title
Stub `validatePerasCert` Unconditionally Accepts Any Crafted Peras Certificate, Enabling Chain-Weight Inflation and Consensus Safety Failure — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that is an explicit stub: it unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. An unprivileged peer can exploit this via the ObjectDiffusion mini-protocol to inject arbitrary crafted `PerasCert` objects. Each accepted certificate inflates the `PerasWeightSnapshot` used by chain selection, allowing the attacker to make a shorter or weaker chain appear heavier than the honest chain, causing the node to switch to a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

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

Every `PerasCert` — regardless of its content, round number, boosted block, or any cryptographic proof — is unconditionally wrapped in `Right ValidatedPerasCert`. No signature, committee membership, quorum, or round-validity check is performed.

**Inbound certificate processing calls this stub directly:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` — the production path for certificates received from peers — passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`. Because the stub always returns `Right`, `processCerts` always reaches the "all certs are valid" branch and calls `addPerasCertAsync` for every certificate in the batch.

**Accepted certificates are accumulated into the `PerasWeightSnapshot`:** [3](#0-2) 

`implGetWeightSnapshot` builds the snapshot by iterating over every stored certificate and calling `addToPerasWeightSnapshot` with the boosted block point and boost weight. A fraudulent certificate pointing to any block on a weaker fork adds that block's boost to the snapshot.

**Chain selection consumes the inflated snapshot:** [4](#0-3) 

`weightedSelectView` computes `wsvWeightBoost = weightBoostOfFragment weights frag` from the snapshot. `wsvTotalWeight` then sums block number and boost: [5](#0-4) 

`preferCandidate` switches to the candidate chain whenever `wsvTotalWeight cand > wsvTotalWeight ours`: [6](#0-5) 

An attacker who injects enough fraudulent certificates boosting blocks on a shorter fork can make that fork's total weight exceed the honest chain's total weight, causing the node to roll back and adopt the attacker's chain.

**The `chainSelSync` path confirms the trigger:** [7](#0-6) 

`chainSelSync` for `ChainSelAddPerasCert` reads the current chain, adds the certificate to `PerasCertDB`, and then re-runs chain selection using the updated weight snapshot. This is the exact "sync" trigger analogous to `syncCash` in the external report.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Connect via the ObjectDiffusion mini-protocol for Peras certificates.
2. Send a batch of crafted `PerasCert` objects, each claiming to boost a block on a shorter adversarial fork.
3. Because `validatePerasCert` always returns `Right`, all certificates pass and are stored.
4. The `PerasWeightSnapshot` is inflated with fraudulent boosts.
5. Chain selection compares `wsvTotalWeight` and switches to the adversarial fork.
6. The node rolls back its honest chain and adopts an invalid or non-canonical chain.

This is a **consensus safety failure**: an honest node is made to prefer a non-canonical chain solely through crafted network messages, with no stake majority, key compromise, or operator action required.

---

### Likelihood Explanation

The vulnerability is active whenever Peras is enabled. The CHANGELOG confirms the chain selection machinery is already wired up and functional:

> "Make the ChainDB aware of the PerasCertDB, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length."

The stub is the **only** `validatePerasCert` implementation in the codebase for the default `BlockSupportsPeras` instance. Any private testnet or staging environment that enables Peras is immediately exploitable by any connected peer. The attack requires no special privileges, no key material, and no prior chain knowledge beyond identifying a block hash to boost.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. The certificate's round number is within the valid range relative to the current chain tip.
2. The boosted block exists and is on a known chain fragment.
3. The certificate carries a valid aggregate BLS signature (or equivalent) from a quorum of eligible committee members, verified against the stake distribution for that round.
4. The committee membership proofs (VRF outputs) are valid for each signer.

Until real validation is in place, the ObjectDiffusion writer for Peras certificates (`makePerasCertPoolWriterFromChainDB`) should reject all inbound certificates with an explicit error rather than silently accepting them via the stub.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Attacker mines a short fork `F` branching off block `B` at height `N`.
2. Attacker connects to an honest node and sends via ObjectDiffusion a batch of `PerasCert` objects, each with `pcCertBoostedBlock = blockPoint B` and `pcCertRound` set to distinct round numbers.
3. Each certificate passes `validatePerasCert` (stub always returns `Right`) and is stored in `PerasCertDB`.
4. `implGetWeightSnapshot` returns a snapshot where `B` has accumulated boost weight = `perasWeight params * numberOfCerts`.
5. `chainSelSync` re-runs chain selection; `wsvTotalWeight` for fork `F` now exceeds the honest chain's total weight.
6. The node rolls back to `B` and adopts fork `F`, diverging from the honest chain.

The attacker controls the magnitude of the boost by simply sending more certificates (each with a distinct `pcCertRound`), since the deduplication check in `processCerts` only filters by round number: [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-510)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
```
