### Title
Peras Vote Signature Verification Bypass Allows Any Peer to Forge Votes for Arbitrary Pools — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `PerasVote blk` type lacks a cryptographic signature field, and the production `validatePerasVote` implementation only checks stake-distribution membership without verifying vote authenticity. Any unprivileged peer can forge votes claiming to be from any pool in the stake distribution, accumulate enough stake to reach quorum, and cause a fraudulent Peras certificate to be generated — boosting a non-canonical block's chain weight and potentially diverting honest nodes to a weaker chain.

---

### Finding Description

**Analog mapping.** The external report's root cause is an identity-alias bypass: a check that should prevent the same entity from repeatedly claiming a benefit fails because the entity can present a different (alias) identity each time. In the Peras vote path the same structural flaw exists: the deduplication check uses `(voterId, roundNo)` as the vote identity, but there is no proof that the sender actually controls the key behind `voterId`. A single malicious peer can therefore present a different pool's `PerasVoterId` for each forged vote, bypassing the per-voter deduplication exactly as user A bypasses the referral check by cycling through alias addresses.

**Root cause — missing signature field.** The concrete `PerasVote blk` type carries only three fields:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [1](#0-0) 

There is no `VoteSignature` field. Compare this with the WFALS committee `Vote` type, which carries a mandatory `VoteSignature crypto` (and, for non-persistent members, a `VRFOutput crypto`):

```haskell
data Vote crypto WFALS
  = WFALSPersistentVote    !SeatIndex !(ElectionId crypto) !(VoteCandidate crypto) !(VoteSignature crypto)
  | WFALSNonPersistentVote !SeatIndex !(ElectionId crypto) !(VoteCandidate crypto) !(VRFOutput crypto) !(VoteSignature crypto)
``` [2](#0-1) 

**Root cause — stub `validatePerasVote`.** The only production implementation of `validatePerasVote` (the default `BlockSupportsPeras` instance) performs a single lookup in the stake distribution and unconditionally accepts the vote if the voter ID is present:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

No signature is checked because the `PerasVote` type carries none. The stake distribution (`PerasVoteStakeDistr`) is a public `Map PerasVoterId PerasVoteStake`; any peer can enumerate all eligible pool IDs from it.

**Attacker-controlled entry path.** Inbound votes arrive via the Peras vote diffusion mini-protocol and are processed by `processVotes`:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
``` [4](#0-3) 

The deduplication filter uses `getPerasVoteId`, which is `(pviRoundNo, pviVoterId)`:

```haskell
instance HasPerasVoteId (PerasVote blk) blk where
  getPerasVoteId vote = PerasVoteId { pviRoundNo = pvVoteRound vote, pviVoterId = pvVoteVoterId vote }
``` [5](#0-4) 

Because each forged vote uses a *different* pool's `PerasVoterId`, every forged vote passes the deduplication filter and reaches `validateVote`. Since `validateVote` only checks stake-distribution membership, all forged votes are accepted and forwarded to `implAddVote`:

```haskell
implAddVote perasCfg PerasVoteDbEnv{..} vote = do
  let voteId = getPerasVoteId vote
  ...
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [6](#0-5) 

`tryAddVote` calls `updatePerasRoundVoteStates`, which accumulates stake and forges a certificate once `stakeAboveThreshold` is satisfied:

```haskell
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [7](#0-6) 

The default quorum threshold is `3/4 + 2/100 = 77%` of total stake. A peer that enumerates enough pools from the public stake distribution and forges one vote per pool can trivially exceed this threshold.

---

### Impact Explanation

Once a fraudulent certificate is generated, it is stored in the `PerasVoteDB` and propagated. The certificate carries a `perasWeight` boost of 15 slots:

```haskell
perasWeight = PerasWeight 15
``` [8](#0-7) 

Chain selection on honest nodes uses this boost when comparing chains, so a block backed by a fraudulent certificate will be preferred over a longer honest chain that lacks a certificate. This is a **High** chain-selection bug: an unprivileged peer can make honest nodes prefer a non-canonical, adversarially chosen block, weakening the security guarantees of the Peras protocol.

---

### Likelihood Explanation

**High.** The attack requires only:
1. A network connection to an honest node (any peer).
2. Knowledge of the current `PerasVoteStakeDistr` (public, derivable from the ledger state).
3. The ability to construct `PerasVote` messages with arbitrary `pvVoteVoterId` values — no private key material is needed because the vote type carries no signature.

No stake, no key compromise, and no social engineering are required.

---

### Recommendation

1. **Add a signature field to `PerasVote blk`.** The type must carry a `VoteSignature` (and, for non-persistent members, a VRF output) so that `validatePerasVote` can cryptographically verify the vote, mirroring the WFALS `Vote` type. [2](#0-1) 

2. **Implement `validatePerasVote` to verify the signature** against the pool's public key from the stake distribution, rejecting any vote whose signature does not verify. [3](#0-2) 

3. **Implement `validatePerasCert` to verify the aggregate signature** — the current stub also unconditionally accepts all certificates. [9](#0-8) 

---

### Proof of Concept

```
Attacker (any peer) → honest node:

1. Query ledger for PerasVoteStakeDistr:
     { pool_A → 0.20, pool_B → 0.20, pool_C → 0.20, pool_D → 0.20 }

2. Forge four PerasVote messages for round R, targeting adversarial block B*:
     PerasVote { pvVoteRound = R, pvVoteBlock = B*, pvVoteVoterId = pool_A }
     PerasVote { pvVoteRound = R, pvVoteBlock = B*, pvVoteVoterId = pool_B }
     PerasVote { pvVoteRound = R, pvVoteBlock = B*, pvVoteVoterId = pool_C }
     PerasVote { pvVoteRound = R, pvVoteBlock = B*, pvVoteVoterId = pool_D }
     (No private keys needed — PerasVote carries no signature field.)

3. Send all four votes to the honest node via the Peras vote mini-protocol.

4. processVotes:
     - Each vote has a distinct (voterId, roundNo) → passes deduplication.
     - validatePerasVote finds each pool_X in stakeDistr → accepts with stake 0.20.

5. implAddVote accumulates stake: 0.20 + 0.20 + 0.20 + 0.20 = 0.80 > 0.77 (quorum).
   → ValidatedPerasCert forged for B* with boost = 15 slots.

6. Honest node's chain selection now prefers B* over the canonical chain
   (unless the canonical chain is more than 15 slots ahead).
``` [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L565-570)
```haskell
instance HasPerasVoteId (PerasVote blk) blk where
  getPerasVoteId vote =
    PerasVoteId
      { pviRoundNo = pvVoteRound vote
      , pviVoterId = pvVoteVoterId vote
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L179-191)
```haskell
  data Vote crypto WFALS
    = WFALSPersistentVote
        !SeatIndex
        !(ElectionId crypto)
        !(VoteCandidate crypto)
        !(VoteSignature crypto)
    | WFALSNonPersistentVote
        !SeatIndex
        !(ElectionId crypto)
        !(VoteCandidate crypto)
        !(VRFOutput crypto)
        !(VoteSignature crypto)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-198)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-212)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
