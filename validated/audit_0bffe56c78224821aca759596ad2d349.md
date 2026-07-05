### Title
Missing Peras Certificate Cryptographic Validation Allows Unauthorized Chain Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate catch-all `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate, performing zero cryptographic or structural validation. This instance is the only one in the codebase and applies to all block types via `instance StandardHash blk => BlockSupportsPeras blk`. The `processCerts` inbound handler calls this function as the sole validation gate before accepting peer-supplied Peras certificates and forwarding them to chain selection. An unprivileged peer can therefore send a forged certificate boosting any block in the node's VolatileDB, causing the node to apply a 15-block weight boost to that block's chain and potentially switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the method responsible for verifying that a received Peras certificate is cryptographically valid (aggregate BLS signature, quorum of legitimate committee members, correct round/block target). The degenerate instance that covers all block types implements this as an unconditional success:

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

This instance is the only one in the codebase, applied universally:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

The production network handler wires this directly into the inbound Peras certificate diffusion mini-protocol:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [4](#0-3) 

`processCerts` calls `validateCert` on each inbound certificate and accepts all that return `Right`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

Because `validatePerasCert` always returns `Right`, every certificate from every peer passes this gate. The accepted certificate is then forwarded to `ChainDB.addPerasCertAsync`, which enqueues it for `chainSelSync`. There, if the boosted block exists in the VolatileDB, `chainSelectionForBlock` is triggered for it:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

The certificate's boost weight (`perasWeight = PerasWeight 15`) is applied to the boosted block's chain during comparison, potentially causing the node to prefer a chain that is up to 14 honest blocks shorter than the current selection. [7](#0-6) 

---

### Impact Explanation

**High. Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

An adversary who has already delivered a valid block to the target node (so it exists in the VolatileDB) can send a forged Peras certificate claiming to boost that block. The node accepts the certificate without any cryptographic check, applies a 15-block weight boost to the block's chain, and may switch away from the honest canonical chain to the adversary's fork. This violates the chain selection invariant that only legitimately certified blocks receive weight boosts, and can cause the node to permanently diverge from the honest chain for the duration the forged certificate remains in the PerasCertDB.

---

### Likelihood Explanation

**High.** The attack requires only a network connection to the target node and knowledge of any block hash in the node's VolatileDB (obtainable via ChainSync). No keys, stake, or privileged access are needed. The forged certificate needs only a valid `PerasRoundNo` and a `Point blk` referencing the target block — both are trivially constructable. The production node-to-node handler is already wired to accept Peras certificates from all connected peers.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic validation before the Peras certificate diffusion mini-protocol is enabled in production. At minimum, the validation must verify:

1. The aggregate BLS signature over the `(roundNo, boostedBlock)` message against the aggregated public keys of the claimed voters.
2. That each claimed voter is a legitimate committee member with sufficient stake.
3. That the total stake of the voters meets the quorum threshold.

The real validation logic already exists in `Ouroboros.Consensus.Committee.WFALS` (`implVerifyCert`) and `Ouroboros.Consensus.Committee.EveryoneVotes` (`implVerifyCert`). The `BlockSupportsPeras` instance for production Cardano blocks must be wired to the appropriate committee scheme rather than using the degenerate catch-all instance. [8](#0-7) 

Until real validation is in place, the Peras certificate diffusion mini-protocol must not be enabled on production nodes.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Connect to a target node as a peer via the node-to-node protocol.
2. Observe a block hash `h` from the node's VolatileDB via ChainSync (any recent block on a candidate chain).
3. Construct a `PerasCert` with any `pcCertRound` and `pcCertBoostedBlock = BlockPoint slot h`.
4. Send this certificate via the Peras certificate diffusion mini-protocol (`hPerasCertDiffusionClient`).
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}`.
6. The certificate is added to `PerasCertDB` and `addPerasCertAsync` is called.
7. `chainSelSync` finds block `h` in the VolatileDB and calls `chainSelectionForBlock` for it.
8. Chain selection now treats the chain containing `h` as having 15 extra blocks of weight, potentially causing the node to switch to the adversary's fork. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-494)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```
