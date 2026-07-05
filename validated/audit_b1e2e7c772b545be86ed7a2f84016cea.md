### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Artificially Boost Chain Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The degenerate `BlockSupportsPeras` instance used for all block types unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. Any unprivileged peer can craft and send a `PerasCert` for any block, which will be accepted as a `ValidatedPerasCert` carrying a full `perasWeight` boost and immediately trigger chain selection. This allows an attacker to artificially inflate the Peras weight of any fork, causing honest nodes to prefer a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate is stored and used in chain selection. The production instance — applied to all block types — is a stub that always returns `Right`:

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

No signature, quorum, committee membership, round validity, or boosted-block existence check is performed. The function is called on every inbound certificate in both production writers:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)

-- makePerasCertPoolWriterFromChainDB
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` on each received certificate and, if all pass, forwards them to `addCert` (which calls `addPerasCertAsync` on the `ChainDB`): [3](#0-2) 

`addPerasCertAsync` stores the certificate in `PerasCertDB` and triggers chain selection for the boosted block: [4](#0-3) 

Chain selection now uses Peras weight (total weight = block number + sum of boosts), as confirmed by the CHANGELOG:

> "Make the ChainDB aware of the PerasCertDB, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length." [5](#0-4) 

The `perasWeight` boost assigned to every accepted certificate is drawn directly from `PerasParams`: [6](#0-5) 

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` naming any `pcCertBoostedBlock` (any block hash/slot on any fork).
2. Send it over the Peras certificate diffusion mini-protocol.
3. The receiving node calls `validatePerasCert`, which unconditionally returns `Right ValidatedPerasCert{..}` with a full `perasWeight` boost.
4. The certificate is stored in `PerasCertDB` and `chainSelectionForBlock` is triggered for the boosted block.
5. The node may switch to a fork that is now heavier due to the injected boost, even though no legitimate Peras committee ever voted for it.

This is a **bypass of Peras voting/certificate checks** enabling unauthorized certificate acceptance and a **chain selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical chain — matching both the Critical and High impact tiers in the allowed scope.

### Likelihood Explanation

Any peer connected via the Peras certificate diffusion mini-protocol can exploit this. No keys, stake, or committee membership are required. The attacker only needs to construct a valid CBOR-encoded `PerasCert` (two fields: `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`) and send it. The exploit is deterministic and requires no brute force. Likelihood is **High** whenever Peras is enabled on a network.

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` before the Peras feature is enabled in production. At minimum, verify the aggregate BLS signature against the claimed voter set, verify each voter's committee eligibility (VRF proof for non-persistent members), and verify that the claimed quorum stake threshold is met.
2. Until real validation is implemented, **gate the Peras certificate diffusion path** so that it is unreachable when Peras is disabled, preventing the stub from being reachable even in a misconfigured deployment.
3. Track the linked issue (`https://github.com/tweag/cardano-peras/issues/120`) to ensure the TODO is resolved before any production rollout.

### Proof of Concept

**Setup:** Two nodes, A (honest) and B (attacker), both with Peras enabled. Node A has a current chain `C1` of weight `W`. Node B knows of a fork `C2` with weight `W - delta` (slightly shorter/lighter).

**Attack:**
1. Attacker B constructs a `PerasCert`:
   ```
   PerasCert
     { pcCertRound    = <any valid round number>
     , pcCertBoostedBlock = <tip of fork C2>
     }
   ```
2. B sends this certificate to A via the Peras cert diffusion protocol.
3. A calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
4. A stores the cert and calls `chainSelectionForBlock` for the tip of `C2`.
5. `C2`'s new total weight = `(W - delta) + perasWeight` which, for any `perasWeight > delta`, exceeds `W`.
6. A switches to fork `C2` — a chain that was never legitimately voted for by any Peras committee.

The attacker can repeat this for multiple rounds, permanently biasing chain selection on any honest node toward attacker-chosen forks. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-137)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```
