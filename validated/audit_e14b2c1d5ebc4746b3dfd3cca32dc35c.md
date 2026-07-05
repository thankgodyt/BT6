### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Crafted-Certificate Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` to unconditionally return `Right` (success) for every certificate it receives, performing zero cryptographic or structural checks. This instance is the one used in production for all block types. Because the inbound certificate processing pipeline (`processCerts`) relies entirely on `validatePerasCert` to gate admission into the `PerasCertDB`, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block, triggering chain selection with fraudulent Peras weight and potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the type class that governs Peras certificate and vote handling. Its `validatePerasCert` method is the sole validation gate for inbound certificates. The universal instance at line 320 of `SupportsPeras.hs` — `instance StandardHash blk => BlockSupportsPeras blk` — is the concrete implementation used for all production block types. Its body is:

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

No check is performed on `cert` at all — not the round number, not the boosted block point, not the voter set, and not the aggregate BLS signature. Every certificate, regardless of content, is wrapped in `ValidatedPerasCert` and returned as `Right`.

This function is called directly in the production inbound certificate pipeline. `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (PerasCertDB.getCertIds perasCertDB)
      (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
      (void . join . atomically . PerasCertDB.addCert perasCertDB)
      certs
``` [2](#0-1) 

`processCerts` partitions certificates into valid and invalid using this callback. If any certificate fails, the entire batch is rejected and the peer is disconnected. Because `validatePerasCert` always returns `Right`, no certificate ever fails:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once a certificate is admitted to the `PerasCertDB`, `chainSelSync` processes it. It reads the `pcCertBoostedBlock` from the certificate and, if that block is present in the `VolatileDB`, triggers `chainSelectionForBlock` for it with the full Peras weight boost:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the full configured Peras weight boost. This boost is applied to chain selection for the block named in the certificate's `pcCertBoostedBlock` field — a field the attacker controls freely.

The analog to the vault bug is exact: just as `_withdrawNfts()` deleted `_vaultNfts[_collection][_tokenId]` and transferred the NFT without checking that the mapping value equalled the caller's `_vaultId`, `validatePerasCert` wraps any certificate as `ValidatedPerasCert` without checking that the certificate's voter set, round number, or aggregate signature are legitimate.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with:
- `pcCertRound` set to any round number
- `pcCertBoostedBlock` pointing to any block the target node has in its `VolatileDB` (e.g., a block on a competing fork)
- An empty or garbage `pcVoters` bitmap and a random `pcSignature`

This certificate passes `validatePerasCert`, is stored in the `PerasCertDB`, and causes `chainSelSync` to trigger chain selection for the boosted block with the full `perasWeight` boost. If the boosted block is on a competing fork, the node may switch to that fork, diverging from the canonical chain. Because the attacker can target any block in the VolatileDB and apply the maximum Peras weight to it, they can systematically bias chain selection away from the honest chain.

**Impact class**: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

Any peer connected to the node via the Peras certificate diffusion mini-protocol can send crafted certificates. No stake, no keys, and no special privileges are required. The attack requires only knowledge of a block hash present in the target node's VolatileDB, which is obtainable via normal ChainSync. Likelihood is **High**.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs the full certificate validation required by the Peras protocol:

1. Verify that `pcCertRound` falls within the expected range for the current epoch.
2. Verify that `pcCertBoostedBlock` is a valid, known block point.
3. Reconstruct the voting committee for the relevant epoch and verify that the voter set in `pcVoters` consists of legitimate committee members with sufficient combined stake (quorum check).
4. Verify the aggregate BLS signature `pcSignature` over `(pcCertRound, pcCertBoostedBlock)` using the aggregated public keys of the declared voters.

The existing `Committee.WFALS.implVerifyCert` and `Committee.EveryoneVotes.implVerifyCert` already implement the committee-level certificate verification logic. The `validatePerasCert` implementation should delegate to these after converting the concrete `PerasCert` to the abstract `Committee.Cert` type via `PerasCertCompatibleWithVotingCommittee.fromPerasCert`. [5](#0-4) 

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate diffusion mini-protocol.
2. Observe (via ChainSync) a block hash `H` on a competing fork that is present in the target's VolatileDB.
3. Craft a `PerasCert` with `pcCertRound = r` (any round), `pcCertBoostedBlock = (slot, H)`, an empty `pcVoters` bitmap, and a zeroed `pcSignature`.
4. Send the crafted certificate to the target node.
5. `processCerts` calls `validatePerasCert` on the certificate; it returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
6. The certificate is stored in the `PerasCertDB`.
7. `chainSelSync` reads `pcCertBoostedBlock`, finds block `H` in the VolatileDB, and calls `chainSelectionForBlock` for it with the full Peras weight boost.
8. If the Peras weight boost is sufficient to tip the chain selection comparison, the node switches to the fork containing `H`, diverging from the canonical chain. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs (L67-76)
```haskell
class
  PerasCertCompatibleWithVotingCommittee cert crypto committee
    | cert -> crypto
  where
  toPerasCert ::
    Committee.Cert crypto committee ->
    Either PerasConversionError cert
  fromPerasCert ::
    cert ->
    Either PerasConversionError (Committee.Cert crypto committee)
```
