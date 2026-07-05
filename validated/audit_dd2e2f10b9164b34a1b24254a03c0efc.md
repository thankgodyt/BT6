### Title
Stub `validatePerasCert` Always Returns Success, Allowing Unprivileged Peers to Inject Fake Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or committee-membership checks. Because `processCerts` in the ObjectDiffusion layer calls this function as the sole gate before adding a certificate to the `PerasCertDB` and triggering chain selection, any unprivileged peer can inject an arbitrary `PerasCert` that boosts any block in the VolatileDB, causing the honest node to prefer a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory validation gate for inbound Peras certificates. The only instance in the codebase is a catch-all stub:

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

This stub is wired directly into the production ObjectDiffusion inbound path via `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` reads the set of already-known round numbers, filters duplicates, then calls `validateCert` on each remaining certificate. Because `validateCert` is the stub above, every certificate passes:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

After passing this non-existent gate, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which calls `chainSelSync`. That function adds the cert to `PerasCertDB`, then—if the boosted block is present in the VolatileDB—immediately triggers `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

Chain selection then consults the `PerasWeightSnapshot`, which now includes the attacker-injected boost, and may switch the node to the boosted fork:

```haskell
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight }
``` [5](#0-4) 

The analog to the external report is exact: in the Sound report, platform fees are enforced only at the minter level, and the minter can be replaced with a forked version that skips fee enforcement. Here, certificate validity is enforced only at `validatePerasCert`, and the sole implementation of that function skips all enforcement, allowing any peer to act as a "trusted minter" of Peras certificates.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block in the target node's VolatileDB as the boosted block. The fake certificate passes the stub validator, is stored in `PerasCertDB`, and its weight boost is immediately applied to chain selection. If the boosted block is on a fork, the node may switch away from the canonical chain. Because Peras weight boosts are additive and unbounded in number (one per round), a sustained attacker can continuously inject certificates to keep a node pinned to a non-canonical fork, constituting a chain-selection safety failure.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation

The ObjectDiffusion mini-protocol is a public node-to-node interface. Any peer that can establish a connection can send `PerasCert` objects. No stake, key material, or privileged access is required. The only natural barrier is that the boosted block must already be present in the VolatileDB; however, an attacker who also controls a block-producing node (or who simply waits for a natural fork) can satisfy this condition trivially. The stub is the only implementation in the codebase—there is no override for Cardano-specific block types.

### Recommendation

1. Implement real cryptographic validation inside `validatePerasCert`: verify the aggregate BLS signature over the election identifier and boosted block hash, verify that each claimed voter is a legitimate committee member for the given round (checking VRF eligibility for non-persistent members), and verify that the aggregate voter stake meets the quorum threshold.
2. Until real validation is in place, the ObjectDiffusion certificate inbound path should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.
3. Remove the catch-all `instance StandardHash blk => BlockSupportsPeras blk` stub and replace it with a compile-time error or a clearly-named `NoPerasSupport` newtype, so that any code path that reaches `validatePerasCert` without a real implementation fails loudly at compile time rather than silently accepting all inputs.

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to an honest node via the ObjectDiffusion mini-protocol.
2. Attacker observes (or causes) a natural fork: block `B_fork` exists in the node's VolatileDB but is not on the current chain.
3. Attacker sends a single `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B_fork }` for any round `r` not yet in the node's `PerasCertDB`.
4. `processCerts` filters out already-known rounds (none match), then calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally — no BLS signature check, no committee membership check, no quorum check.
6. The cert is added to `PerasCertDB` via `addPerasCertAsync`.
7. `chainSelSync` detects that `B_fork` is in the VolatileDB and calls `chainSelectionForBlock`.
8. Chain selection computes `totalWeightOfFragment` for all candidate fragments; the fragment containing `B_fork` now has extra `PerasWeight` from the injected certificate.
9. If the boosted fragment's total weight exceeds the current chain's total weight, the node switches to the fork.

**Relevant code locations:**

- Stub validator: [6](#0-5) 
- Inbound processing calling the stub: [7](#0-6) 
- Chain selection triggered by injected cert: [8](#0-7) 
- Weight snapshot used in chain selection: [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L45-50)
```haskell
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight
  }
  deriving stock Eq
  deriving Generic
  deriving newtype NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
