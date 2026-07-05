### Title
Batch-Rejection in `processCerts` Allows an Unprivileged Peer to Suppress Valid Peras Certificates, Corrupting Chain-Selection Weight — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

`processCerts` rejects an **entire batch** of inbound Peras certificates the moment any single certificate in that batch fails validation. An unprivileged peer can craft a batch that mixes one invalid certificate with several valid ones; the valid certificates are silently discarded. Because Peras certificates supply the weight boosts that drive chain selection, suppressing them causes the node to evaluate candidates without those boosts, potentially preferring a less-secure chain. The identical design flaw exists in `processVotes` (`PerasVote.hs`) and is **currently exploitable** because `validatePerasVote` already returns `Left` for unknown voters.

---

### Finding Description

**Root cause — `processCerts`**

```
ouroboros-consensus/src/ouroboros-consensus/
  Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs
  lines 164–185
```

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->                          -- valid certs in `_` are discarded
      throw (PerasCertValidationError errs)
```

`partitionEithers` separates valid from invalid results. When the error list is non-empty the function throws, and the valid certificates captured in `_` are **never passed to `addCert`**. This is structurally identical to the RocketPool bug: a succeeded logical operation (receiving valid certificates) is blocked by a side-condition (one invalid certificate in the same batch) that an attacker controls.

**Current validator status**

The production writer wires in a stub:

```
lines 121–133
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

The default `validatePerasCert` always returns `Right`, so `processCerts` cannot currently throw. However:

1. The TODO comment and linked issue (`tweag/cardano-peras#120`) confirm real validation will replace the stub.
2. The identical pattern in `processVotes` (`PerasVote.hs` lines 178–201) **is currently exploitable** because `validatePerasVote` returns `Left PerasValidationErr` whenever the voter is absent from the stake distribution.

**`processVotes` — currently reachable**

```
ouroboros-consensus/src/ouroboros-consensus/
  Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs
  lines 178–201
```

```haskell
case partitionEithers validationResults of
  ([], validatedVotes) -> mapM_ (addVote . WithArrivalTime now) validatedVotes
  (errs, _)            -> throw (PerasVoteValidationError errs)
```

An attacker sends a batch containing one vote whose `pvVoteVoterId` is absent from the current `PerasVoteStakeDistr`. `validatePerasVote` returns `Left`; the entire batch is thrown away; all valid votes in the batch are lost.

**Entry path**

Both writers are wired into the object-diffusion mini-protocol:

```
makePerasCertPoolWriterFromChainDB  (PerasCert.hs lines 113–137)
makePerasVotePoolWriterFromChainDB  (PerasVote.hs, analogous)
```

Any peer that can speak the object-diffusion protocol (no credentials required) can submit a crafted batch.

---

### Impact Explanation

Peras certificates are the sole source of weight boosts recorded in `PerasWeightSnapshot`. Chain selection in `constructPreferableCandidates` and `preferAnchoredCandidate` uses `weightBoostOfFragment` / `totalWeightOfFragment` to compare candidates:

```
ChainSel.hs lines 762, 777
Diff.rollbackExceedsSuffix weights curChain
preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain
```

If valid certificates are suppressed, the snapshot is incomplete. A candidate chain that should be preferred because its tip block carries a Peras boost will instead be evaluated at bare block-count weight, potentially causing the node to stay on or switch to a less-secure chain. This is a **chain-selection bug triggered by an unprivileged peer** — matching the "High" impact tier: *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

For votes: suppressed votes prevent quorum, preventing certificate generation, which has the same downstream effect on chain-selection weight.

---

### Likelihood Explanation

**`processVotes` (currently exploitable):** The attacker needs only to include one vote whose voter ID is not in the current stake distribution. This is trivially constructable from public chain data. No stake, no keys, and no privileged access are required. A relay-style peer that aggregates votes from multiple honest nodes and injects one crafted vote can suppress an entire round's worth of valid votes in a single batch.

**`processCerts` (latent, activated when stub is replaced):** The same attack applies once real validation is wired in. The TODO comment and the existing `implVerifyCert` logic in `WFALS.hs` (lines 484–600) confirm this path is planned.

---

### Recommendation

Mirror the RocketPool fix: **do not make the critical action (adding valid objects) contingent on the absence of invalid objects in the same batch.** Specifically:

- In `processCerts` and `processVotes`, when `partitionEithers` returns a non-empty error list, **still add the valid objects** (`validatedCerts` / `validatedVotes`) to the database, and only disconnect from the peer (or log the errors) for the invalid ones.
- Alternatively, validate each object individually and add it or reject it independently, so one bad object cannot poison the rest of the batch.

The current all-or-nothing design means a single attacker-controlled invalid object can block an unbounded number of valid objects from ever reaching the node's state.

---

### Proof of Concept

**For `processVotes` (currently exploitable):**

1. Attacker connects as a peer via the object-diffusion mini-protocol.
2. Attacker observes the current Peras round and collects valid votes from honest nodes (publicly diffused).
3. Attacker constructs a batch: `[vote₁_valid, vote₂_valid, …, voteₙ_crafted]` where `voteₙ_crafted` has a `pvVoteVoterId` not present in the current `PerasVoteStakeDistr`.
4. Attacker sends the batch to the victim node via `opwAddObjects`.
5. `processVotes` calls `validatePerasVote` on each vote; `voteₙ_crafted` returns `Left PerasValidationErr`.
6. `partitionEithers` produces a non-empty error list; `throw (PerasVoteValidationError errs)` is executed.
7. `vote₁_valid … vote_{n-1}_valid` are never passed to `addVote`; they are lost.
8. If the attacker can repeat this for enough peers, quorum is not reached, no certificate is generated, and the weight boost for the round's target block is absent from `PerasWeightSnapshot`.
9. `chainSelectionForBlock` evaluates candidates without that boost; the node may prefer a chain that would otherwise have been outweighed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L759-778)
```haskell
              -- Filter out candidates that have less weight than the current
              -- chain. We don't want to needlessly read the headers from disk
              -- for those candidates.
              . NE.filter (not . Diff.rollbackExceedsSuffix weights curChain)
              -- Extend the diff with candidates fitting on @p@
              . Paths.extendWithSuccessors succsOf lookupBlockInfo
              $ diff
        -- We cannot reach the block from the current selection.
        | otherwise -> pure []
  let fragments =
        -- Trim fragments so that they follow the LoE, that is, they extend the LoE
        -- by at most @k@ blocks or are extended by the LoE.
        fmap (trimToLoE loeFrag) $
          diffs
  pure
    [ (chain, reason)
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-372)
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
