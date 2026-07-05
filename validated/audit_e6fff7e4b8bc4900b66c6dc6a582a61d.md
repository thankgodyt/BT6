### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Forged Peras Votes to Manufacture Fraudulent Quorum Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasVote` implementation does not verify the cryptographic signature on inbound votes. Any unprivileged peer can send `PerasVote` messages that claim to originate from arbitrary stake pools. Because the only check performed is a stake-distribution lookup (not a signature check), an attacker can forge votes on behalf of every stake pool in the network, accumulate enough stake-weighted votes to exceed the quorum threshold, and cause the node to forge a fraudulent Peras certificate that boosts an adversarial chain in chain selection.

---

### Finding Description

**Vulnerability class**: Bypass of Peras voting/certificate checks — direct analog of the Shardeum `sync_trie_hashes` multi-vote injection.

**Root cause — `validatePerasVote` stub**

The production `BlockSupportsPeras` instance (the only instance that exists for all `blk`) implements `validatePerasVote` as follows:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The function accepts any vote whose `pvVoteVoterId` field is present in the stake distribution. It performs **no cryptographic signature verification** — the `_params` argument is discarded entirely. A peer can craft a `PerasVote` with an arbitrary `pvVoteVoterId` (any stake pool key hash) and any `pvVoteBlock`, and the vote will be accepted as valid.

**Inbound path — `processVotes`**

Votes received over the object-diffusion mini-protocol are processed by `processVotes`:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb =
          filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  ...
``` [2](#0-1) 

The `validateVote` callback supplied in both production writers is:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

The deduplication key is `PerasVoteId = (pviRoundNo, pviVoterId)`:

```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
``` [4](#0-3) 

This means one vote per `(round, voterId)` pair is accepted. Since there is no signature check, an attacker can submit one forged vote per stake pool in the network, each claiming a different `pvVoteVoterId`, all targeting the same adversarial block.

**Quorum forging — `updatePerasRoundVoteStates` / `updateTargetVoteTally`**

Each accepted vote's stake is accumulated in `PerasTargetVoteTally.ptvtTotalStake`:

```haskell
| (Nothing, votes') <- swapVote vote ptvtVotes =
    (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
``` [5](#0-4) 

When `stakeAboveThreshold` is satisfied, `forgePerasCert` is called automatically:

```haskell
case votesReachQuorum cfg voteList of
  Just votesWithQuorum -> do
    cert <- forgePerasCert cfg votesWithQuorum
    pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
``` [6](#0-5) 

The resulting `ValidatedPerasCert` is then used by chain selection to apply a weight boost to the attacker's chosen block, making the adversarial chain preferred over the honest chain.

**Secondary issue — `validatePerasCert` also a stub**

The same instance unconditionally accepts any certificate:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [7](#0-6) 

This means a certificate received directly over the cert-diffusion path is also accepted without any aggregate-signature verification.

---

### Impact Explanation

An attacker who can connect as a peer (no stake, no keys required) can:

1. Enumerate the stake distribution (public on-chain data).
2. Send one forged `PerasVote` per stake pool, all targeting an adversarial block in the current round.
3. The victim node accumulates these votes, reaches quorum, and forges a `ValidatedPerasCert` boosting the adversarial block.
4. Chain selection now prefers the adversarial chain over the honest chain, constituting a **consensus safety failure**: an honest node accepts an invalid/adversarial chain state.

This matches the **Critical** impact category: bypass of Peras voting checks that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

- **Entry point is fully public**: the object-diffusion mini-protocol is reachable by any peer that can establish a connection to the node.
- **No stake or cryptographic material required**: the attacker only needs knowledge of the current stake distribution (public).
- **No rate-limiting or per-peer vote cap**: `processVotes` accepts any batch of votes from any peer as long as the `(round, voterId)` pair is not already in the DB.
- **Peras is under active development** and these stubs are the only implementations wired into the production pipeline, so any deployment that enables Peras object diffusion is immediately vulnerable.

---

### Recommendation

1. **Implement real signature verification in `validatePerasVote`**: verify the `pvSignature` field against the voter's registered public key (from the stake distribution) before accepting a vote. The `WFALS` committee scheme already shows the correct pattern via `implVerifyVote` which calls `verifyVoteSignature`. [8](#0-7) 

2. **Implement real aggregate-signature verification in `validatePerasCert`**: verify the aggregate BLS signature in the certificate against the claimed voter set before accepting it.

3. **Do not wire stub implementations into the production object-diffusion pipeline** until the above are complete. Gate Peras vote/cert diffusion behind a feature flag that is disabled by default.

4. **Track the open issue**: `https://github.com/tweag/cardano-peras/issues/120` already acknowledges this gap; it should be treated as a security-critical blocker before any Peras-enabled release.

---

### Proof of Concept

```
Attacker (any peer) → connects to victim node via object-diffusion mini-protocol

For each (poolId, stake) in current_stake_distribution:
  send PerasVote {
    pvVoteRound  = current_round,
    pvVoteBlock  = adversarial_block_point,
    pvVoteVoterId = poolId          -- no signature required
  }

processVotes filters by PerasVoteId=(round, poolId) → each vote is "new"
validatePerasVote checks only: Map.lookup poolId stakeDistr → succeeds for all
updateTargetVoteTally accumulates stake for adversarial_block_point
stakeAboveThreshold → True → forgePerasCert called
ValidatedPerasCert{vpcCertBoost=perasWeight} stored in PerasVoteDB

Chain selection now applies weight boost to adversarial_block_point,
causing the victim node to prefer the adversarial chain.
```

The `PerasVote` wire type carries `pvVoteVoterId` as a plain `KeyHash StakePool` with no proof of key ownership: [9](#0-8) 

Any peer can set this field to any value, and the stub validator will accept it as long as the key hash appears in the stake distribution.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-142)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L453-459)
```haskell
    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L582-587)
```haskell
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-350)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
```
