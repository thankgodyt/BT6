### Title
Unconditional Acceptance of Peras Certificates Bypasses All Cryptographic and Semantic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Because this stub is wired directly into the live peer-facing certificate ingestion pipeline (`processCerts`), any unprivileged peer can inject an arbitrary crafted `PerasCert` that will be accepted, stored in `PerasCertDB`, and used to trigger chain selection — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The default (degenerate) instance, which is the only instance currently compiled into production, is:

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

This stub is directly consumed by `processCerts`, the function that handles all batches of certificates received from remote peers over the object-diffusion mini-protocol:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass, adds them to the database. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would reject invalid certificates is never taken: [4](#0-3) 

The accepted certificate is then forwarded to `ChainDB.addPerasCertAsync`, which calls `chainSelSync`. That function adds the certificate to `PerasCertDB` and triggers chain selection for the boosted block: [5](#0-4) 

The checks that are entirely absent from `validatePerasCert`:
- **Aggregate BLS signature verification** — the `pcSignature` field of `PerasCert` is never verified against the claimed voters' keys.
- **Round-number validity / expiry** — no check that `pcRoundNo` is within the current or recent round window; a certificate for any past or future round is accepted.
- **Voter eligibility** — no check that the claimed voters were actually eligible for the claimed round.
- **Boosted-block plausibility** — no check that `pcBoostedBlock` is a real block hash known to the network.

The concrete `PerasCert` type used in the V1 BLS implementation carries all these fields: [6](#0-5) 

The `implVerifyCert` functions in `WFALS.hs` and `EveryoneVotes.hs` do perform full cryptographic verification, but they are **never called** on the inbound path — only `validatePerasCert` is, and it is the stub. [7](#0-6) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A crafted certificate claiming to boost a block on a minority fork will be accepted and stored. `chainSelSync` then triggers chain selection for that block, and the artificial boost weight (`perasWeight params = 15` by default) is applied. If the adversary's fork is within the volatile window and the boost tips the weight comparison, the honest node will switch to the adversary's chain. This directly undermines the Peras protocol's chain-quality and common-prefix guarantees.

Additionally, because no round-number expiry is checked, a certificate for an arbitrarily old or future round is accepted — the analog of the missing deadline in the original report. A certificate signed in a past epoch (or a fabricated one with a future round) remains permanently valid from the node's perspective.

---

### Likelihood Explanation

**High.** The vulnerable code path is active in the production object-diffusion pipeline. Any peer connected via the Peras certificate mini-protocol can send a single crafted `PerasCert` message. No stake, no key material, and no prior knowledge of the chain is required — only the ability to construct a CBOR-encoded `PerasCert` with a plausible `pcBoostedBlock` pointing to a block in the peer's volatile window.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature against the claimed voters' public keys (using `implVerifyCert` from `WFALS` or `EveryoneVotes`).
2. Checks that `pcRoundNo` falls within an acceptable window relative to the current round (analogous to a deadline/expiry).
3. Verifies voter eligibility against the stake distribution snapshot for the claimed round.
4. Rejects certificates whose `pcBoostedBlock` is not a known block hash.

Until the real implementation is in place, the certificate ingestion pipeline should refuse all inbound certificates rather than accept them unconditionally.

---

### Proof of Concept

1. Connect to a node running the Peras object-diffusion mini-protocol.
2. Construct a CBOR-encoded `PerasCert` with:
   - `pcRoundNo` = any value (e.g., current round)
   - `pcBoostedBlock` = hash of a block on a minority fork within the volatile window
   - `pcVoters` = any non-empty map (not verified)
   - `pcSignature` = any bytes (not verified)
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
5. The certificate is added to `PerasCertDB` and `chainSelSync` triggers chain selection for the boosted block.
6. The node's chain selection now weights the minority-fork block with `perasWeight = 15` extra boost, potentially causing a chain switch. [8](#0-7) [9](#0-8) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
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
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-495)
```haskell
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
  WFALSCert electionId candidate voters aggSig -> do
```
