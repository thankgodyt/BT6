### Title
Missing Vote Signature Verification in `validatePerasVote` Allows Any Peer to Forge Peras Votes on Behalf of Any Pool - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation in the default `BlockSupportsPeras` instance performs no cryptographic signature check. It only verifies that the claimed voter ID exists in the stake distribution. Any unprivileged peer can therefore submit a `PerasVote` claiming to be from any registered pool, have it accepted as `ValidatedPerasVote`, accumulate fake quorum, and cause the node to forge and accept a Peras certificate boosting an attacker-chosen block.

---

### Finding Description

The `BlockSupportsPeras` default instance in `SupportsPeras.hs` implements `validatePerasVote` as a stub:

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
``` [1](#0-0) 

The only check performed is `lookupPerasVoteStake vote stakeDistr` — i.e., whether the `PerasVoterId` embedded in the vote exists in the stake distribution. There is **no verification that the vote carries a valid cryptographic signature from the claimed pool's key**. The `_params` argument (which would carry the cryptographic configuration) is discarded entirely.

This stub is the catch-all instance (`instance StandardHash blk => BlockSupportsPeras blk`) and is therefore the active implementation for all block types until a more specific instance is provided. [2](#0-1) 

The network-facing inbound path calls this validation directly. `processVotes` in `PerasVote.hs` receives a batch of votes from a peer, calls `validateVote` (which resolves to `validatePerasVote`), and on success stores each result as a `ValidatedPerasVote` in the `PerasVoteDB`:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (...) votes
    mapM validateVote votesNotAlreadyInDb
  ...
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
``` [3](#0-2) 

`makePerasVotePoolWriterFromChainDB` wires this directly to the production `ChainDB.addPerasVoteWithAsyncCertHandling`: [4](#0-3) 

Once enough fake votes accumulate in `PerasVoteDB`, `implAddVote` calls `updatePerasRoundVoteStates`, which triggers `forgePerasCert` and stores the resulting `ValidatedPerasCert`: [5](#0-4) 

The forged certificate then boosts the attacker-chosen block's chain weight in Peras chain selection.

The analog to the external report is exact: `check_signer = false` → any caller can act on behalf of any account. Here, `_params` discarded and no signature check → any peer can act on behalf of any pool.

---

### Impact Explanation

An unprivileged peer can submit crafted `PerasVote` messages claiming to be from any pool registered in the current stake distribution. Because `validatePerasVote` only checks stake-distribution membership and never verifies the vote's cryptographic signature, these votes are accepted as `ValidatedPerasVote`. Once the attacker accumulates enough fake votes to reach quorum for a target block of their choosing, the node internally forges a `ValidatedPerasCert` boosting that block. This constitutes:

- **Bypass of Peras vote authorization**: the node accepts votes that were never signed by the claimed pool's key.
- **Unauthorized certificate acceptance**: a certificate is forged and stored from votes that carry no valid proof of origin.
- **Chain-selection manipulation**: the boosted block gains Peras weight, potentially causing the honest node to prefer a non-canonical chain.

This falls under the **Critical** allowed impact: *Bypass of PBFT/Praos/TPraos/Peras voting or certificate checks that enables unauthorized vote or certificate acceptance.*

---

### Likelihood Explanation

- **Attacker precondition**: none beyond establishing a standard peer connection (object-diffusion miniprotocol). No keys, no stake, no privileged access required.
- **Attack complexity**: trivial. The attacker only needs to know which pool IDs exist in the current stake distribution (public on-chain data) and craft `PerasVote` structs with those IDs.
- **Detectability**: none at the validation layer; the stub explicitly discards the cryptographic parameters.

---

### Recommendation

Replace the stub `validatePerasVote` with a full implementation that:

1. Looks up the pool's registered **vote verification key** from the committee/stake-distribution context.
2. Verifies the vote's cryptographic signature against that key, the election ID, and the vote candidate — analogous to `verifyVoteSignature` already used in `implVerifyVote` for both `EveryoneVotes` and `WFALS` committee schemes.
3. Returns `Left PerasValidationErr` (or a richer error) on any signature failure.

The `PerasCfg blk` parameter (currently `_params`) must be threaded through to carry the cryptographic configuration needed for verification.

---

### Proof of Concept

1. Node is running with the default `BlockSupportsPeras` instance.
2. Attacker reads the current stake distribution to enumerate valid `PerasVoterId` values (pool IDs).
3. Attacker connects via the object-diffusion miniprotocol and sends a batch of `PerasVote` objects, each carrying a different legitimate pool ID as `pvVoteVoterId`, all targeting the same `(pvVoteRound, pvVoteBlock)` of the attacker's choice. No valid signatures are included.
4. `processVotes` calls `validatePerasVote` for each vote; each passes because `lookupPerasVoteStake` finds the pool ID in the stake distribution.
5. Each vote is stored as `ValidatedPerasVote` in `PerasVoteDB`.
6. Once cumulative stake of the fake votes crosses the quorum threshold, `implAddVote` → `updatePerasRoundVoteStates` → `forgePerasCert` produces a `ValidatedPerasCert` boosting the attacker's chosen block.
7. The node's chain selection now treats that block as having Peras boost weight, potentially diverging from the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-152)
```haskell
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-236)
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
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr
```
