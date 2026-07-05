### Title
Peras Certificate Validation Bypass Allows Any Peer to Inject Fake Chain-Weight Boosts — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum verification. Any unprivileged peer can send a crafted `PerasCert` message over the object-diffusion mini-protocol, have it accepted as valid, and cause the victim node to apply a `PerasWeight` boost of 15 to an arbitrary block, potentially triggering a chain switch to a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as an unconditional success:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
``` [1](#0-0) 

No signature, no quorum check, no committee membership check — every certificate is accepted.

**The `PerasCert` wire type carries no signature field:**

The degenerate `PerasCert` data type contains only a round number and a block point:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound        :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

There is nothing to verify even if the code tried. (The real BLS-signed `V1.PerasCert` in `Ouroboros.Consensus.Peras.Cert.V1` carries `pcSignature`, but it is not yet wired into the production validation path.) [3](#0-2) 

**Production inbound path — `processCerts` → `addPerasCertAsync`:**

`makePerasCertPoolWriterFromChainDB` is the production writer used by the cert-diffusion mini-protocol. It passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [4](#0-3) 

`processCerts` calls `validateCert` on each inbound cert; since it always returns `Right`, every cert is timestamped and forwarded to `addPerasCertAsync`: [5](#0-4) 

**Chain selection is triggered for the boosted block:**

`chainSelSync` for `ChainSelAddPerasCert` adds the cert to `PerasCertDB` and then calls `chainSelectionForBlock` for the block named in the certificate: [6](#0-5) 

**Chain comparison uses the injected weight:**

`preferAnchoredCandidate` computes `weightedSelectView` over each fragment, summing `PerasWeight` boosts from the `PerasWeightSnapshot`. A fake cert for a block on a shorter fork adds `perasWeight = 15` to that fork's total weight, potentially making it preferred over the honest chain: [7](#0-6) [8](#0-7) 

The default `perasWeight` is 15, meaning a single fake certificate makes a chain appear 15 blocks heavier: [9](#0-8) 

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An attacker with no keys and no stake can:
1. Craft a `PerasCert` naming any block in the victim's VolatileDB as the boosted block.
2. Send it over the cert-diffusion mini-protocol.
3. Cause the victim to add 15 weight units to that block's chain.
4. If the attacker's preferred fork is within 15 blocks of the honest tip, the victim switches to it.

Multiple fake certs for the same block accumulate weight (the snapshot sums boosts per point), so the attacker can inject arbitrarily large weight with repeated messages. This breaks the Peras chain-selection invariant that only quorum-certified blocks receive boosts, and can cause honest nodes to diverge from the canonical chain.

### Likelihood Explanation

Peras is disabled by default on mainnet but is enabled in private testnets and integration environments (the CHANGELOG explicitly notes "if Peras is disabled (which is the default), there is no observable difference"). The object-diffusion mini-protocol is a standard peer-to-peer channel; any connected peer can send cert messages. No keys, stake, or special privileges are required. The `PerasCert` wire format is trivially constructable (two integers: a round number and a block point). The attack is deterministic and requires only a single message per desired weight unit.

### Recommendation

1. **Immediate**: Gate the entire Peras cert/vote inbound path behind a feature flag that is `False` until real cryptographic validation is wired in. Reject all inbound certs when the flag is off, rather than accepting them with a stub validator.
2. **Before enabling Peras**: Replace the degenerate `validatePerasCert` with a real implementation that verifies the aggregate BLS signature (`pcSignature` in `V1.PerasCert`) against the committee's aggregate verification key and confirms quorum was reached, as the `Committee.Class.verifyCert` interface already specifies.
3. **Similarly for votes**: `validatePerasVote` in the same degenerate instance checks only stake-distribution membership but not the BLS vote signature (`pvSignature` in `V1.PerasVote`). Apply the same fix. [10](#0-9) 

### Proof of Concept

**Setup**: A private testnet with Peras enabled and two nodes, A (honest) and B (attacker). Node B is a peer of node A.

**Steps**:

1. Node A has an honest chain of length N. Node B has a fork of length N−5 (shorter, normally not preferred).
2. Node B identifies a block hash `H` on its fork that is in node A's VolatileDB (i.e., node A has seen this block).
3. Node B constructs a `PerasCert` with `pcCertRound = 1` and `pcCertBoostedBlock = (slot_of_H, hash_of_H)` — no signature required.
4. Node B sends this cert to node A via the cert-diffusion mini-protocol.
5. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
6. Node A adds the cert to `PerasCertDB` and calls `chainSelectionForBlock` for block `H`.
7. Node A's `preferAnchoredCandidate` now computes: honest chain total weight = N, fork total weight = (N−5) + 15 = N+10. Fork wins.
8. Node A switches to node B's shorter fork.

**Expected outcome**: Node A diverges from the canonical chain, accepting a fork that would normally be rejected under honest Praos chain selection.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-60)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-174)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L63-87)
```haskell
instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L116-123)
```haskell
  -- | Verify a certificate attesting the winner of a given election
  verifyCert ::
    VotingCommittee crypto committee ->
    Cert crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (NE [EligibilityWitness crypto committee])

```
