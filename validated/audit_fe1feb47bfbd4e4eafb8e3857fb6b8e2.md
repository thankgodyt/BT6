### Title
Peras Certificate and Vote Validation Bypassed by No-Op `validatePerasCert`/`validatePerasVote` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional `Right` (no-op) and `validatePerasVote` with only a stake-distribution membership check — no cryptographic signature verification. Any unprivileged peer can send crafted `PerasCert` or `PerasVote` objects over the object-diffusion miniprotocol that pass "validation" and are stored in `PerasCertDB`/`PerasVoteDB`, triggering chain selection for an adversary-chosen block.

---

### Finding Description

**Root cause — `SupportsPeras.hs` lines 350–371:**

The only `BlockSupportsPeras` instance is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` (the comment explicitly calls it "degenerate"). Its two validation methods are:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [1](#0-0) 

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [2](#0-1) 

- `validatePerasCert` accepts **every** certificate unconditionally — no round-number bounds, no aggregate-signature check, no VRF proof, no committee membership check.
- `validatePerasVote` only checks that the claimed voter ID appears in the stake distribution; it does **not** verify the vote's cryptographic signature.

**Inbound path — `PerasCert.hs` lines 103 and 126:**

Both the isolated-DB writer and the production ChainDB writer call `validatePerasCert mkPerasParams` directly:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

`processCerts` passes every certificate that is not already in the DB through this no-op validator and then calls `addCert`: [5](#0-4) 

**Chain-selection trigger — `ChainSel.hs` line 531:**

Once a certificate is stored in `PerasCertDB`, `chainSelSync` immediately calls `chainSelectionForBlock` for the boosted block, potentially switching the node to an adversary-chosen chain:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

**Vote path — `PerasVote.hs` lines 111 and 141:**

The production vote writer calls `validatePerasVote mkPerasParams sd vote`, which only checks stake-distribution membership: [7](#0-6) [8](#0-7) 

Forged votes accumulate in `PerasVoteDB`; once quorum is reached, `updatePerasRoundVoteStates` forges a certificate internally, which is then fed into the same chain-selection path. [9](#0-8) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification enabling unauthorized chain selection.**

An adversary who can connect as a peer can:

1. **Certificate path**: Send a single crafted `PerasCert` naming any block hash and any round number. `validatePerasCert` returns `Right` unconditionally. The certificate is stored and `chainSelectionForBlock` is triggered for the adversary-chosen block, potentially causing the honest node to switch to a non-canonical chain with a Peras weight boost it did not legitimately earn.

2. **Vote path**: Send `PerasVote` messages claiming to be any pool operator present in the stake distribution (no signature required). Once enough forged votes accumulate to exceed the quorum threshold, a certificate is forged internally and the same chain-selection trigger fires.

Both paths allow an unprivileged network peer to manipulate Peras-weighted chain selection without holding any cryptographic key, directly violating the Peras security assumption that only legitimate committee members can boost a block.

---

### Likelihood Explanation

**High.** The object-diffusion miniprotocol is reachable by any peer that can establish a connection. The attack requires only knowledge of a valid pool ID in the current stake distribution (publicly available on-chain) and the ability to send a well-formed CBOR-encoded `PerasCert` or `PerasVote` message. No key material, stake, or privileged access is needed. The TODO comments and the linked issue (`cardano-peras/issues/120`) confirm the missing validation is a known, unresolved gap in the current production code.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation — verify the aggregate BLS vote signature against the declared voter set, verify each VRF output via `batchVerifyVRFOutputs` (with linearization to defeat swap attacks), check that the round number is within the current epoch's valid range, and confirm the boosted block hash is a known recent block.

2. **`validatePerasVote`**: Add cryptographic signature verification of the vote using the voter's registered BLS verification key before accepting the vote as `ValidatedPerasVote`.

3. Until real validation is wired in, the object-diffusion inbound handlers for Peras objects should either be disabled or gated behind a feature flag so that crafted network messages cannot reach `PerasCertDB`/`PerasVoteDB` and trigger chain selection.

---

### Proof of Concept

**Certificate injection (single message, no key required):**

```
1. Attacker connects to a Cardano node running Peras-enabled consensus.
2. Attacker sends a PerasCert CBOR message:
     { pcCertRound = <current round>, pcCertBoostedBlock = <adversary block point> }
   over the object-diffusion miniprotocol.
3. processCerts calls validatePerasCert mkPerasParams cert
   → returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
   (no signature check, no committee check, no round-range check)
4. addCert stores the certificate in PerasCertDB.
5. chainSelSync triggers chainSelectionForBlock for the adversary-chosen block.
6. If the adversary block is in VolatileDB, the node may switch to the adversary's chain.
```

Relevant code path: [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-127)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L109-113)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-148)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
