### Title
Peras Vote Signature Entirely Absent from `PerasVote` Type and `validatePerasVote` — Unprivileged Peer Can Forge Votes for Any Eligible Committee Member - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance defines a `PerasVote` data type that carries no cryptographic signature field, and its `validatePerasVote` implementation only checks whether the claimed voter ID appears in the stake distribution. No proof of key possession is required. The production inbound-vote processing path (`makePerasVotePoolWriterFromChainDB`) calls this stub validator directly. An unprivileged peer can therefore send crafted vote messages claiming to be any eligible committee member, accumulate a forged quorum, and cause the node to accept a manufactured Peras certificate that boosts an arbitrary block in chain selection.

### Finding Description

The catch-all instance

```haskell
instance StandardHash blk => BlockSupportsPeras blk
```

is the only `BlockSupportsPeras` instance in the codebase. It defines `PerasVote` as:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

There is no signature field. The corresponding validator is:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check performed is `lookupPerasVoteStake`, which is a plain `Map.lookup` on the voter ID. No cryptographic proof of identity is required or possible.

The companion `validatePerasCert` is even weaker — it unconditionally returns `Right`:

```haskell
-- TODO: perform actual validation …
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

Both stubs are wired into the production inbound-processing paths. `makePerasVotePoolWriterFromChainDB` passes `validatePerasVote mkPerasParams sd vote` as the validator for every vote received from a peer, and `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` for every certificate received from a peer.

### Impact Explanation

An unprivileged peer can:

1. Enumerate the public stake distribution to identify eligible voters.
2. Craft `PerasVote` messages claiming to be those voters (no key material needed).
3. Send the batch to a target node; `processVotes` calls `validatePerasVote`, which passes because the voter ID is present in the stake distribution.
4. Once enough forged votes accumulate, `votesReachQuorum` fires, `forgePerasCert` is called, and a `ValidatedPerasCert` is produced for an attacker-chosen block.
5. The certificate is enqueued via `addPerasCertAsync`, triggering `chainSelectionForBlock` for the boosted block.

The result is unauthorized Peras certificate acceptance and attacker-controlled chain-selection boosts — a bypass of Peras voting checks that enables an honest node to prefer a non-canonical chain without any stake majority.

### Likelihood Explanation

The attack requires only network access and knowledge of the public stake distribution (both freely available). No keys, no stake, no operator access. The production vote-diffusion mini-protocol is the entry point. The stub validator is the universal instance for all block types; there is no override for `CardanoBlock`.

### Recommendation

1. Add a cryptographic signature field to `PerasVote` (analogous to the `sig` field in `EveryoneVotesVote` and `WFALSPersistentVote`).
2. Implement `validatePerasVote` to verify that signature against the voter's public key from the stake distribution before accepting the vote.
3. Implement `validatePerasCert` to verify the aggregate BLS signature (as done in `implVerifyCert` for `EveryoneVotes` and `WFALS`).
4. Remove the degenerate catch-all instance or gate it behind a compile-time flag that cannot be activated for production block types.

### Proof of Concept

**Step 1 — `PerasVote` has no signature field.** [1](#0-0) 

**Step 2 — `validatePerasVote` only checks stake-distribution membership; no signature is verified.** [2](#0-1) 

**Step 3 — `validatePerasCert` unconditionally returns `Right` (no validation).** [3](#0-2) 

**Step 4 — Production inbound-vote path calls the stub validator for every peer-supplied vote.** [4](#0-3) 

**Step 5 — Production inbound-cert path calls the stub validator for every peer-supplied certificate.** [5](#0-4) 

**Step 6 — `processVotes` accepts all votes that pass `validateVote` and adds them to the DB; a quorum triggers certificate generation.** [6](#0-5) 

**Step 7 — A forged certificate triggers `chainSelectionForBlock`, boosting the attacker-chosen block in chain selection.** [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
