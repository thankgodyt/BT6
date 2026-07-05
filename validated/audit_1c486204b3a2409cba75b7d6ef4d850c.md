### Title
Peras Certificate Verification Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance unconditionally accepts every inbound `PerasCert` without verifying any cryptographic proof, quorum, or committee eligibility. Because the production object-diffusion path feeds inbound certificates directly through this stub validator before adding them to the `PerasCertDB` and triggering chain selection, an unprivileged peer can craft a certificate that boosts an arbitrary block, granting it extra `PerasWeight` and potentially causing honest nodes to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate that must be passed before a certificate is accepted. The universal default instance — applied to every block type — implements this gate as an unconditional pass:

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

No aggregate BLS signature is checked, no committee membership is verified, and no quorum threshold is enforced. The instance is declared with `instance StandardHash blk => BlockSupportsPeras blk`, making it the active instance for all block types until a more specific one is provided. [2](#0-1) 

The production object-diffusion writer for the `ChainDB` path calls this stub directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

and for certificates:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

`processCerts` then adds every certificate that passes this non-validation to the database: [5](#0-4) 

Once in the `PerasCertDB`, `chainSelSync` uses the certificate to trigger chain selection for the boosted block, adding `PerasWeight` to it: [6](#0-5) 

Chain selection then compares total weight (block number + weight boost) and may switch to the boosted chain: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block it controls as the boosted block. Because `validatePerasCert` returns `Right` unconditionally, the certificate is accepted, stored, and used to add `perasWeight` (a configurable `PerasWeight` boost) to that block's chain weight. If the boosted block is on a fork that is otherwise shorter than the honest chain, the artificial weight boost can make it appear heavier, causing honest nodes to switch to the attacker's fork. This is a **chain-selection safety failure** triggered by a single crafted network message from an unprivileged peer — no stake, no keys, no prior relationship required.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the production diffusion layer. Any connected peer can submit `PerasCert` objects. The attack requires only constructing a well-formed CBOR-encoded `PerasCert` struct (round number + boosted block point) — no cryptographic material is needed because the signature check is entirely absent. The attack is therefore trivially executable by any peer that can open a connection to the node.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before Peras is enabled on any network. At minimum, verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the public keys of the claimed voters, check that each claimed voter is a legitimate committee member in the correct epoch, and confirm the total stake of signers meets the quorum threshold.

2. **Gate the object-diffusion path** so that inbound certificates are rejected (and the peer disconnected) when no real validator is in place, rather than silently accepting everything.

3. **Remove or guard the universal default instance** (`instance StandardHash blk => BlockSupportsPeras blk`) so that enabling Peras on a new block type requires an explicit, reviewed implementation rather than silently inheriting the no-op stub.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the Peras certificate object-diffusion mini-protocol.

2. Attacker constructs a minimal PerasCert:
     PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <attacker's fork tip> }
   No BLS keys, no VRF proofs, no voter list needed.

3. Attacker sends the cert. processCerts calls:
     validatePerasCert mkPerasParams cert
   which returns Right unconditionally.

4. The cert is stored in PerasCertDB. chainSelSync fires
   chainSelectionForBlock for the boosted block.

5. weightedSelectView now computes:
     wsvTotalWeight = BlockNo(fork tip) + perasWeight params
   If perasWeight is large enough, the fork's total weight exceeds
   the honest chain's total weight.

6. preferCandidate returns ShouldSwitch; the honest node adopts
   the attacker's fork.
``` [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
