### Title
Peras Certificate Validation Unconditionally Returns `Right`, Allowing Any Peer-Supplied Certificate to Bypass All Cryptographic and Semantic Checks - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic checks. This implementation is wired directly into the live Peras certificate inbound pipeline (`makePerasCertPoolWriterFromChainDB`), which is the path used when a peer delivers certificates over the network. Any unprivileged peer can therefore inject arbitrary certificates that boost any block, triggering chain selection and potentially causing the node to switch to a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate that must accept or reject a certificate before it is stored and acted upon. The sole production instance of this typeclass (the `StandardHash blk =>` catch-all instance) implements this gate as an unconditional pass-through:

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

The `PerasCert.V1` module explicitly acknowledges that serialization performs only minimal structural checks and that "additional semantic and cryptographic checks must be performed on the certificate later on." [2](#0-1) 

Those later checks are never performed. The `validatePerasCert` stub is the only validation gate, and it always succeeds.

This stub is wired into the production inbound pipeline in `makePerasCertPoolWriterFromChainDB`, which is the writer used when the node receives certificates from peers over the network:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`processCerts` calls this validator on every inbound certificate and, because it always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`chainSelSync` then processes the certificate: it adds it to the `PerasCertDB`, looks up the boosted block in the `VolatileDB`, and triggers chain selection for that block, potentially switching the node to a different chain: [5](#0-4) 

The checks that a real `validatePerasCert` must perform — but which the stub skips entirely — include:

- BLS aggregate signature verification over `(pcRoundNo, pcBoostedBlock)` (the `pcSignature` field in `Peras.Cert.V1.PerasCert`)
- Committee membership and seat-index validity for every voter in `pcVoters`
- Non-persistent voter VRF eligibility proof verification
- Quorum threshold: the total stake of the signers must exceed the Peras quorum parameter
- Round number plausibility relative to the current epoch/slot [6](#0-5) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the node's `VolatileDB`. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to boost that block's weight in chain selection. If the boosted block is the tip of a fork, the node will switch to that fork. This constitutes:

- **Bypass of Peras certificate/signature validation** enabling unauthorized certificate acceptance (Critical per scope).
- **Chain selection manipulation** letting an unprivileged peer make an honest node prefer a non-canonical chain (High per scope).

### Likelihood Explanation

The Peras certificate object diffusion mini-protocol is a standard peer-to-peer channel. Any connected peer — including an adversarial one — can send `PerasCert` objects. No special privileges, keys, or stake are required. The attack requires only that the adversary know the hash of a block already in the target node's `VolatileDB` (easily obtained via the ChainSync protocol). Likelihood is **High** once Peras is active on a network running this code.

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs all required checks before returning `Right`:

1. Verify the BLS aggregate signature over `(pcRoundNo, pcBoostedBlock)` against the aggregate public key derived from the claimed voter set.
2. Verify each voter's committee membership and seat index against the epoch's committee snapshot.
3. Verify non-persistent voters' VRF eligibility proofs.
4. Check that the total stake of the signers meets the Peras quorum threshold (`perasQuorumThreshold`).
5. Check that `pcCertRound` is plausible given the current slot/epoch.

Until a real implementation is available, the inbound pipeline should reject all certificates rather than accept all of them (fail-closed rather than fail-open).

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion mini-protocol
     → makePerasCertPoolWriterFromChainDB.opwAddObjects
     → processCerts ... (validatePerasCert mkPerasParams) ...
     → validatePerasCert always returns Right
     → ChainDB.addPerasCertAsync (crafted cert)
     → chainSelSync ChainSelAddPerasCert
     → VolatileDB.getBlockComponent (attacker-chosen block hash)
     → chainSelectionForBlock  ← node may switch chain
```

**Minimal crafted certificate (using the stub `PerasCert` type):**

```haskell
craftedCert :: PerasCert TargetBlock
craftedCert = PerasCert
  { pcCertRound      = PerasRoundNo currentRound
  , pcCertBoostedBlock = BlockPoint forkTipSlot forkTipHash
  }
-- validatePerasCert mkPerasParams craftedCert == Right (ValidatedPerasCert ...)
-- No signature, no committee check, no quorum check performed.
```

The attacker sends this certificate over the object diffusion channel. `processCerts` calls `validatePerasCert mkPerasParams craftedCert`, receives `Right`, timestamps it, and calls `ChainDB.addPerasCertAsync`. `chainSelSync` then boosts `forkTipHash` and may trigger a chain switch. [7](#0-6) [8](#0-7) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L11-13)
```haskell
-- NOTE: the validation performed during serialization is minimal, and does not
-- cover any of additional semantic and cryptographic checks that must be
-- performed on the certificate later on.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-62)
```haskell
-- | Concrete Peras certificates using BLS signatures
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
  }
  deriving (Show, Eq)
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
