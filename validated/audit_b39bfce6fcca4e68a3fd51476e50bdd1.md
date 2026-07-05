### Title
Peras Vote and Certificate Validation Universally Bypassed by Degenerate `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole `BlockSupportsPeras` instance in the codebase is a catch-all degenerate placeholder that implements `validatePerasCert` to unconditionally return `Right` (success) without performing any validation, and implements `validatePerasVote` to skip all cryptographic signature verification. Because no more-specific instance exists for any block type, this stub is the only implementation used in production. An unprivileged peer can therefore forge Peras votes for any voter present in the stake distribution, accumulate enough fake stake-weighted votes to reach quorum, trigger certificate forging, and cause a node to apply an unearned Peras weight boost to a non-canonical block during chain selection.

---

### Finding Description

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` defines the `BlockSupportsPeras` type class and provides a single, universally-applicable instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

This instance provides three critically deficient method implementations:

**1. `validatePerasCert` — always succeeds, no validation performed:**

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
``` [2](#0-1) 

Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost.

**2. `validatePerasVote` — checks only stake-distribution membership, skips all signature verification:**

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
``` [3](#0-2) 

A vote is accepted as valid if and only if the `pvVoteVoterId` field appears in the stake distribution map. No KES/VRF/BLS signature over the vote content is checked. The voter ID (`KeyHash StakePool`) is public on-chain data.

**3. `getPerasCertInBlock` — always returns `Nothing`:** [4](#0-3) 

No Peras certificate is ever extracted from a block, so the certificate-in-block path is currently inert. However, the vote-processing path is live.

**The vote-processing entry point** is `processVotes` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`, called from `makePerasVotePoolWriterFromChainDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
``` [5](#0-4) 

`processVotes` filters already-seen votes, then calls `validateVote` on each new one. Because `validatePerasVote` only checks stake-distribution membership, any peer that knows a pool's `KeyHash StakePool` (public information) can submit a structurally valid `PerasVote` record for that pool without possessing its private key. [6](#0-5) 

Once enough forged votes accumulate to exceed the quorum threshold, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a `ValidatedPerasCert` with the full `perasWeight` boost. That boost is then applied during chain selection, causing the node to prefer the attacker-chosen block.

The `votesReachQuorum` helper confirms that quorum is determined purely by summing `vpvVoteStake` values returned by `validatePerasVote` — values that were assigned without any signature check: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. Enumerate all `PerasVoterId` values (public stake-pool key hashes) from the ledger state.
2. Craft `PerasVote` messages for those voters targeting any block point of the attacker's choice.
3. Submit them to a victim node via the Peras vote diffusion mini-protocol.
4. Because `validatePerasVote` accepts any vote whose voter ID appears in the stake distribution, all forged votes pass validation.
5. Once the accumulated `PerasVoteStake` exceeds the quorum threshold, a `ValidatedPerasCert` is forged and stored.
6. The certificate's `vpcCertBoost` (= `perasWeight params`) is applied to the targeted block in chain selection, causing the node to prefer a non-canonical chain.

This constitutes a **bypass of Peras voting and certificate checks that enables unauthorized certificate acceptance and chain-selection manipulation** — matching the "Critical" impact tier in the allowed scope.

---

### Likelihood Explanation

- The voter IDs required to forge votes are public on-chain data (stake-pool key hashes).
- No private key material, stake majority, or operator access is needed.
- The vote diffusion mini-protocol is an externally reachable network entry point.
- The degenerate instance is the **only** `BlockSupportsPeras` instance in the repository; no more-specific override exists for any Cardano block type.
- The `processVotes` code path is wired into `makePerasVotePoolWriterFromChainDB`, which is part of the production node's object-diffusion layer.

Likelihood is **High** once the Peras vote diffusion protocol is active on a network running this code.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasVote`: verify the vote's BLS/KES/VRF signature against the voter's registered verification key before accepting it.
2. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate signature and quorum membership proof embedded in the certificate.
3. Until real implementations are ready, **gate the entire Peras vote-processing path** behind a feature flag so that the degenerate instance cannot be reached from the network.
4. Remove or replace the universal `instance StandardHash blk => BlockSupportsPeras blk` with a compile-time error (e.g., via `error` or a `TypeError` constraint) so that any code path reaching these methods without a proper instance fails loudly rather than silently accepting all inputs.

---

### Proof of Concept

```
Attacker node A connects to victim node V via the Peras vote diffusion mini-protocol.

1. A reads the current PerasVoteStakeDistr from V's ledger state
   (or derives it from the public stake distribution).

2. For each PerasVoterId pid in the distribution with stake s_i:
     A sends PerasVote { pvVoteRound = r, pvVoteBlock = <attacker_block>, pvVoteVoterId = pid }

3. V calls processVotes → validatePerasVote for each vote.
   validatePerasVote checks: Map.lookup pid stakeDistr → Just s_i → Right (ValidatedPerasVote vote s_i)
   No signature is checked. All votes pass.

4. updatePerasRoundVoteStates accumulates stake. Once Σ s_i > quorumThreshold + safetyMargin,
   forgePerasCert is called → ValidatedPerasCert { vpcCertBoost = perasWeight params }.

5. Chain selection on V now applies perasWeight to <attacker_block>,
   causing V to prefer the attacker's non-canonical chain.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-272)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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
