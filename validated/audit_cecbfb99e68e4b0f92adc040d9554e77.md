### Title
Missing Peras Vote Signature Verification Allows Unauthorized Vote and Certificate Acceptance — (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

### Summary
The default `BlockSupportsPeras` instance's `validatePerasVote` accepts any vote from a registered voter without verifying its cryptographic signature, and `validatePerasCert` unconditionally accepts every certificate without any check. An unprivileged peer can submit forged votes on behalf of any registered stake pool and forged certificates for any block, bypassing Peras voting authorization entirely and causing the node to apply an unearned chain-selection boost to an attacker-chosen block.

### Finding Description
**Root cause — `validatePerasVote` (lines 360–371):**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check performed is whether the claimed `pvVoterId` appears in the stake distribution. The `pvSignature` field carried by the vote is never inspected. Any peer can craft a `PerasVote` with an arbitrary `pvVoteRound`, `pvVoteBlock`, and any registered `pvVoterId`, and the function returns `Right` with the full ledger stake of that pool.

**Root cause — `validatePerasCert` (lines 350–358):**

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

This unconditionally returns `Right` for every certificate, assigning it the full `perasWeight params` chain-selection boost. No aggregate BLS signature, quorum threshold, or any other authorization check is performed.

**Reachable production path:**
`makePerasVotePoolWriterFromChainDB` (PerasVote.hs line 141) binds `validatePerasVote` as the validator and passes it to `processVotes` (PerasVote.hs line 182), which is invoked for every batch of inbound votes received from a peer over the object-diffusion mini-protocol. The `validatePerasCert` path is similarly wired into certificate ingestion.

### Impact Explanation
An unprivileged peer can:
1. Read the public stake distribution to enumerate registered pool IDs.
2. Craft `PerasVote` messages claiming to be those pools, with arbitrary signatures and an attacker-chosen target block.
3. `validatePerasVote` accepts each vote because only stake-distribution membership is checked; the forged signatures are ignored.
4. Once enough forged votes accumulate to cross the quorum threshold, `updatePerasRoundVoteStates` forges a certificate for the attacker's block.
5. Alternatively, the attacker submits a `PerasCert` directly; `validatePerasCert` returns `Right` unconditionally, granting the block `perasWeight params` boost.
6. Chain selection now prefers the attacker's block over the honest canonical tip.

This is a bypass of Peras voting and certificate authorization checks, enabling unauthorized certificate acceptance and a chain-selection error where an honest node permanently prefers a non-canonical block.

### Likelihood Explanation
High. The attacker needs only a live peer connection and knowledge of registered pool IDs (public on-chain data). No keys, stake, or operator access are required. The missing check is structural — the signature field is never read — so there is no partial mitigation.

### Recommendation
1. In `validatePerasVote`, verify `pvSignature` against the voter's BLS public key (looked up from the committee/stake distribution) over the canonical message `hash(pvRoundNo ‖ pvBoostedBlock)` before accepting the vote.
2. In `validatePerasCert`, verify the aggregate BLS signature against the claimed voters' public keys, confirm the quorum threshold is met, and check that the certificate's `electionId` and `candidate` are consistent with the current round context.
3. Remove the degenerate `instance StandardHash blk => BlockSupportsPeras blk` catch-all once concrete per-era instances with real validation are in place, so that a missing override causes a compile error rather than silently falling back to the no-op stub.

### Proof of Concept
```
1. Attacker connects as a peer via the object-diffusion mini-protocol.
2. Attacker reads the on-chain stake distribution; selects N pool IDs whose
   combined stake exceeds the Peras quorum threshold.
3. For each pool ID p_i, attacker constructs:
     PerasVote { pvRoundNo    = <current round>
               , pvBoostedBlock = <attacker's target block hash>
               , pvVoterId    = p_i
               , pvSignature  = <arbitrary bytes> }
4. Attacker sends the batch to the node.
5. processVotes → validatePerasVote: lookupPerasVoteStake finds p_i in the
   distribution → returns Right with full stake; signature is never checked.
6. After N votes, updatePerasRoundVoteStates detects quorum and forges a
   ValidatedPerasCert for the attacker's block with boost = perasWeight params.
7. Chain selection now prefers the attacker's block over the honest chain tip.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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
