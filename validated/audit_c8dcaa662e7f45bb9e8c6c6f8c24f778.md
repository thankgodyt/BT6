### Title
Peras Vote and Certificate Validation Bypass via Missing BLS Signature Checks Enables Unauthorized Chain Boost — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasVote` by checking only stake-distribution membership while completely omitting BLS signature verification, and implements `validatePerasCert` as an unconditional `Right` (no checks at all). Because no Cardano-specific override exists, this degenerate instance is the one used in the production vote-ingestion path. An unprivileged peer can craft votes with valid voter IDs but forged BLS signatures, accumulate enough of them to reach quorum, and cause the node to generate and accept a certificate that boosts an attacker-chosen block, triggering chain selection toward a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is a typeclass defined in `SupportsPeras.hs`. Its only concrete instance is a universal catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

This instance provides two critically incomplete validation functions:

**1. `validatePerasCert` — unconditional accept:**

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

Every certificate, regardless of its `pcRoundNo`, `pcBoostedBlock`, `pcVoters`, or `pcSignature`, is accepted unconditionally.

**2. `validatePerasVote` — stake-distribution lookup only:**

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

The only check performed is whether `pvVoteVoterId` appears in the stake distribution. The `pvSignature` (BLS vote signature), `pvVoteRound`, `pvVoteBlock`, and `pvEligibilityProof` fields are never inspected. The concrete V1 vote type (`Ouroboros.Consensus.Peras.Vote.V1.PerasVote`) carries all of these fields: [4](#0-3) 

The BLS cryptographic infrastructure to verify these signatures exists and is fully implemented (`verifyVoteSignature`, `verifyAggregateVoteSignature`, `batchVerifyVRFOutputs` in `Peras/Crypto/BLS.hs`): [5](#0-4) 

It is simply never called from the validation path.

**No Cardano-specific override exists.** A `grep` across the entire repository for `BlockSupportsPeras` finds only the universal instance in `SupportsPeras.hs` and two test-only files. The degenerate instance is therefore the one resolved for all production block types.

---

### Impact Explanation

The production vote-ingestion entry point is `makePerasVotePoolWriterFromChainDB`, which calls `processVotes` with `validatePerasVote mkPerasParams sd vote` as the validation callback: [6](#0-5) 

`processVotes` accepts all votes that pass validation and stores them via `addPerasVoteWithAsyncCertHandling`: [7](#0-6) 

`addPerasVoteWithAsyncCertHandling` in `ChainSel.hs` automatically generates a certificate when quorum is reached and immediately enqueues it for chain selection: [8](#0-7) 

The certificate processing path in `chainSelSync` then calls `chainSelectionForBlock` for the boosted block, potentially switching the node to a different chain: [9](#0-8) 

The end-to-end consequence: an attacker who knows any set of valid voter IDs (publicly derivable from the stake distribution) can fabricate votes with arbitrary `pvVoteBlock` targets and forged `pvSignature` values. Because `validatePerasVote` never checks the signature, these votes pass validation, accumulate to quorum, produce a certificate for an attacker-chosen block, and trigger chain selection toward that block — bypassing the entire Peras voting security model.

---

### Likelihood Explanation

The Peras vote mini-protocol is a peer-to-peer object-diffusion protocol reachable by any connected peer without authentication. The stake distribution is public on-chain data, so valid voter IDs are trivially enumerable. The attacker needs only to send a batch of votes whose `pvVoteVoterId` fields map to entries in the current stake distribution; no cryptographic material is required. The `processVotes` function disconnects a peer only if validation fails, but since the degenerate `validatePerasVote` never fails for a known voter ID, the attacker is not disconnected. This is straightforwardly exploitable by any peer on a network where Peras is active.

---

### Recommendation

1. **Implement a Cardano-specific `BlockSupportsPeras` instance** (tracked in issue #73) that calls `verifyVoteSignature` / `batchVerifyVRFOutputs` / `verifyAggregateVoteSignature` from `Peras.Crypto.BLS` inside `validatePerasVote` and `validatePerasCert`.
2. Until that instance exists, **gate the Peras vote/cert diffusion mini-protocol** so it is not activated on any network where the degenerate instance is in use.
3. `validatePerasCert` must additionally verify: the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)`, the voter bitmap against the known committee, and each non-persistent voter's VRF eligibility proof.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer (attacker)
  → sends PerasVote batch via object-diffusion mini-protocol
  → makePerasVotePoolWriterFromChainDB.opwAddObjects
  → processVotes
  → validatePerasVote mkPerasParams stakeDistr vote
      -- only checks: Map.lookup pvVoteVoterId stakeDistr
      -- NEVER checks: pvSignature (BLS), pvVoteRound, pvVoteBlock, pvEligibilityProof
  → ValidatedPerasVote accepted
  → addPerasVoteWithAsyncCertHandling (quorum reached)
  → addPerasCertAsync → chainSelSync (ChainSelAddPerasCert)
  → chainSelectionForBlock for attacker-chosen boostedBlock
  → node may switch to attacker-controlled chain
```

**Crafted vote structure (using V1 types):**

```haskell
PerasVote
  { pvRoundNo         = <current round>
  , pvBoostedBlock    = <attacker-chosen block hash>
  , pvSeatIndex       = <any valid seat index from stake distribution>
  , pvEligibilityProof = <arbitrary/zeroed proof>   -- never checked
  , pvSignature       = <arbitrary/zeroed BLS sig>  -- never checked
  }
```

Sending `quorumThreshold / minStakePerVoter` such votes (all with distinct valid `pvSeatIndex` values from the public stake distribution) is sufficient to trigger certificate generation and chain selection for the attacker-chosen block. [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L162-170)
```haskell
  verifyVoteSignature
    pk
    roundNo
    boostedBlock
    (PerasBLSCryptoVoteSignature sig) =
      BLS.verifyWithRole @SIGN
        pk
        (hashVoteSignature roundNo boostedBlock)
        sig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
