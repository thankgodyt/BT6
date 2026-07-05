### Title
`validatePerasCert` Stub Unconditionally Accepts All Peras Certificates, Enabling Fraudulent Chain-Weight Injection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` instance used for all block types contains a stub `validatePerasCert` that unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This is the only instance wired into the production Peras certificate ingest pipeline. An unprivileged peer can send crafted `PerasCert` objects via the Peras certificate object-diffusion mini-protocol; every such certificate passes "validation," is stored in the `PerasCertDB`, and its weight boost is applied during chain selection, allowing the peer to manipulate which chain an honest node prefers.

### Finding Description

**Root cause — stub validation always succeeds**

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory gate before a certificate may be stored or acted upon. The only concrete instance in the codebase is the catch-all degenerate instance:

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

No BLS aggregate-signature check, no committee-membership check, no round-number sanity check, and no boosted-block existence check is performed. The function wraps the raw, unverified `PerasCert` directly into a `ValidatedPerasCert`.

**Ingest pipeline — the stub is the live gate**

`makePerasCertPoolWriterFromChainDB` (the production writer used by the Peras certificate object-diffusion mini-protocol) passes this stub as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, because the stub always returns `Right`, every certificate passes and is forwarded to `addCert`: [3](#0-2) 

**Chain-selection consequence**

Once stored in the `PerasCertDB`, the certificate's weight boost is included in the `PerasWeightSnapshot` read by `chainSelectionForBlock`. `chainSelSync` for `ChainSelAddPerasCert` immediately triggers chain selection for the boosted block: [4](#0-3) 

The `preferAnchoredCandidate` comparison uses these weights, so a fraudulent certificate can tip the balance and cause the node to switch to a fork it would otherwise reject.

**Analog to the reported pattern**

The original report describes `listVesting` checking `sellable` but `completePurchase` omitting the same check — a validation present at one stage is absent at the completion stage. Here, `validatePerasCert` is the declared validation gate, but its implementation is a no-op stub, so the check is absent at the only stage where it is invoked before the certificate influences consensus state.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for any round number and any block hash, send it via the Peras certificate diffusion mini-protocol, and have it unconditionally accepted. The accepted certificate applies a weight boost (`perasWeight params`) to the attacker-chosen block during chain selection. By targeting a block on a minority fork, the attacker can cause honest nodes to prefer that fork over the canonical chain — a chain-selection safety failure. This matches the **High** impact category: *"chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions,"* and also touches the **Critical** category: *"bypass of certificate/vote checks that enables unauthorized certificate acceptance."*

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a public, unauthenticated peer-to-peer channel. Any node that connects to a Peras-enabled node can send crafted certificates. No stake, no keys, and no prior relationship are required. The exploit is deterministic and requires only a single well-formed CBOR-encoded `PerasCert` message.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the claimed committee members' public keys.
2. Verifies each voter's committee-membership eligibility proof (`PerasVoteEligibilityProof`).
3. Checks that the round number is within the acceptable window relative to the current chain tip.
4. Checks that the boosted block hash is a known, valid block.

Until the real implementation is in place, the ingest pipeline should refuse all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.

### Proof of Concept

1. Connect to a Peras-enabled node as an unprivileged peer.
2. Construct a `PerasCert` with `pcCertRound = R` (any round) and `pcCertBoostedBlock = H` (hash of a block on a minority fork).
3. Send the certificate via the Peras certificate object-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
5. The certificate is stored in `PerasCertDB`; `chainSelSync` triggers `chainSelectionForBlock` for block `H`.
6. `preferAnchoredCandidate` now sees the boosted weight for the fork containing `H` and may switch the node's selection to that fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
