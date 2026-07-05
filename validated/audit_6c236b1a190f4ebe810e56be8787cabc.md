### Title
Missing Vote Signature Verification in `validatePerasVote` Allows Unauthorized Peras Certificate Forging — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance — the production implementation for all block types — provides a `validatePerasVote` function that accepts any vote whose claimed voter ID appears in the stake distribution, without verifying any cryptographic proof that the vote was actually cast by that voter. The degenerate `PerasVote` data type does not even carry a signature field, making verification structurally impossible. An unprivileged peer can submit fake votes impersonating arbitrary high-stake voters, accumulate enough stake to exceed the quorum threshold, and cause the node to forge a fraudulent Peras certificate that boosts an attacker-chosen block in chain selection.

This is the direct analog of the external report: the claimed voter identity (`pvVoteVoterId`) is used to look up and credit stake — just as `amount` controls the deposit — while the actual cryptographic proof (the missing signature) is never validated against the claim, just as `msg.value` is never checked against `amount`.

---

### Finding Description

**Root cause — missing signature field and no signature check**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal instance `instance StandardHash blk => BlockSupportsPeras blk` (marked with the comment *"TODO: degenerate instance for all blks to get things to compile"*) is the only `BlockSupportsPeras` instance in the codebase and therefore the one used in production for every block type.

The `PerasVote` data type defined inside this instance carries no signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

The `validatePerasVote` implementation only checks whether the claimed voter ID is present in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

`lookupPerasVoteStake` performs a pure `Map.lookup` on `pvVoteVoterId`:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
```

There is no signature to verify, and no check is performed. Any vote that names a voter ID present in the stake distribution is unconditionally accepted and credited with that voter's full stake weight.

**Production call path**

`validatePerasVote` is called inside `processVotes` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
```

`processVotes` is invoked by both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`, which are the production writers that handle inbound Peras votes received from network peers via the object-diffusion mini-protocol.

**Exploit flow**

1. Attacker reads the current `PerasVoteStakeDistr` (publicly derivable from the ledger state).
2. Attacker crafts `PerasVote` messages naming high-stake voter IDs, targeting an arbitrary block in the current round.
3. Attacker sends these votes to a node via the Peras vote diffusion protocol.
4. `processVotes` calls `validatePerasVote` on each vote; all pass because the voter IDs exist in the distribution.
5. Each accepted vote is timestamped and stored in the `PerasVoteDB` with the impersonated voter's full stake weight.
6. Inside `implAddVote` → `updatePerasRoundVoteStates`, the accumulated stake is compared against the quorum threshold via `stakeAboveThreshold`.
7. Once the threshold is exceeded, `forgePerasCert` is called and a certificate is stored for the attacker's chosen block.
8. The certificate carries `vpcCertBoost = perasWeight params`, which is applied to chain selection, causing the node to prefer the boosted block over the honest canonical chain.

**Secondary issue — `validatePerasCert` is also a no-op**

The same instance's `validatePerasCert` unconditionally returns `Right` for every certificate:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

Any certificate received over the network is accepted without any check on round number, boosted block validity, or aggregate signature.

---

### Impact Explanation

**Impact: High** — Chain selection / Peras voting bypass.

An unprivileged peer can forge a Peras certificate for any block of its choosing by submitting structurally valid but cryptographically unauthenticated votes. The forged certificate is stored in the `PerasVoteDB` and its boost weight is applied during chain selection, causing an honest node to prefer a non-canonical chain. This directly undermines the Peras finality guarantee and can cause persistent chain divergence between nodes that received the fake certificate and those that did not.

This falls within the allowed scope: *"Bypass of… Peras voting or certificate checks… that enables unauthorized… vote, or certificate acceptance"* and *"Chain selection… bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

**Likelihood: Low.**

The attack requires the Peras vote diffusion mini-protocol to be active and reachable. The stake distribution is public, so no privileged information is needed. The primary barrier is whether Peras is enabled on the target network. The degenerate instance is explicitly marked as a placeholder, suggesting the protocol is not yet fully deployed on mainnet, but the code is compiled and linked into production binaries and the diffusion infrastructure is wired up.

---

### Recommendation

1. **Add a signature field** to the `PerasVote` data type so that vote authenticity can be verified.
2. **Implement proper signature verification** in `validatePerasVote` — verify the vote signature against the voter's public key from the stake distribution before crediting the vote's stake weight.
3. **Implement proper certificate validation** in `validatePerasCert` — verify the aggregate BLS signature and all constituent fields before accepting a certificate.
4. Until a complete implementation is in place, **gate the Peras vote diffusion protocol** behind a feature flag that is disabled by default, preventing unauthenticated votes from reaching `processVotes`.

---

### Proof of Concept

```
Precondition: Peras vote diffusion protocol is active on the target node.

1. Query the node's ledger state to obtain the current PerasVoteStakeDistr
   (a public map from PerasVoterId → PerasVoteStake).

2. Select the current Peras round number R and a target block B
   (e.g., an attacker-controlled or minority-chain block).

3. For each high-stake voter V_i in the distribution (until cumulative
   stake exceeds perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin):

     Craft:  PerasVote { pvVoteRound  = R
                       , pvVoteBlock  = B
                       , pvVoteVoterId = V_i }

4. Send all crafted votes to the target node via the object-diffusion
   mini-protocol (PerasVote channel).

5. processVotes calls validatePerasVote for each vote.
   validatePerasVote performs only Map.lookup pvVoteVoterId stakeDistr
   → returns Right for every vote (no signature check).

6. updatePerasRoundVoteStates accumulates stake; stakeAboveThreshold
   returns True once the threshold is exceeded.

7. forgePerasCert is called → a ValidatedPerasCert for block B is stored
   in the PerasVoteDB with vpcCertBoost = perasWeight params.

8. Chain selection now applies the boost to block B, causing the node
   to prefer B over the honest canonical tip.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-210)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
```
