### Title
Peras Vote Signature Verification Bypass Allows Any Peer to Impersonate Legitimate Voters and Forge Quorum Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasVote` without any cryptographic signature check. The `PerasVote` data type carries no signature field at all. Any unprivileged peer can craft a `PerasVote` claiming to be any voter present in the stake distribution, and the vote will pass validation and be accepted into the `PerasVoteDB`. Once enough such forged votes accumulate for a single target block, the node will forge a Peras certificate boosting that block, directly manipulating chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that decides whether an inbound vote is legitimate before it is stored and counted toward quorum. The production catch-all instance (marked with a TODO as a "degenerate instance for all blks to get things to compile") implements this gate as:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check performed is whether the `pvVoteVoterId` field of the vote is a key present in the stake distribution map. No cryptographic signature is verified — and crucially, the `PerasVote` data type itself contains no signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

Because the voter identity is a plain `PerasVoterId` (a `KeyHash StakePool`) with no accompanying proof of possession, any peer that knows the key hash of a legitimate stakepool — which is public information on-chain — can construct a `PerasVote` impersonating that pool.

The inbound processing path in `makePerasVotePoolWriterFromChainDB` calls `processVotes`, which calls `validatePerasVote` and, on success, timestamps the vote and forwards it to `ChainDB.addPerasVoteWithAsyncCertHandling`. Inside `implAddVote` (also carrying a TODO noting missing validation), the vote is counted toward quorum via `updatePerasRoundVoteStates`. When the accumulated stake crosses the quorum threshold, a `ValidatedPerasCert` is forged and stored, boosting the attacker-chosen block's chain weight.

Additionally, `validatePerasCert` in the same instance unconditionally returns `Right` for every certificate it receives, meaning any crafted certificate sent over the wire is also accepted without any check.

---

### Impact Explanation

An unprivileged peer can:

1. Enumerate legitimate stakepool key hashes from the public ledger state.
2. Craft `PerasVote` messages claiming to be those pools, voting for an attacker-chosen block.
3. Send the batch to a victim node via the ObjectDiffusion mini-protocol.
4. `processVotes` accepts all votes (stake-distribution membership check passes; no signature check exists).
5. `updatePerasRoundVoteStates` accumulates the forged stake; once quorum is reached, a `ValidatedPerasCert` is forged for the attacker's target block.
6. The certificate boosts that block's Peras weight, causing the node's chain-selection logic to prefer the attacker-controlled chain over the honest chain.

This is a **Critical** bypass of vote/certificate verification: an unauthorized peer can manufacture quorum for any block, breaking Peras consensus safety.

---

### Likelihood Explanation

The attack requires only knowledge of stakepool key hashes (public on-chain data) and the ability to connect to a node via the standard peer-to-peer network. No keys, stake, or privileged access are needed. The ObjectDiffusion mini-protocol is reachable by any peer. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase and is used in the production `makePerasVotePoolWriterFromChainDB` path.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (e.g., a KES or VRF-backed signature over `(pvVoteRound, pvVoteBlock)` under the pool's operational key).
2. Implement `validatePerasVote` to verify that signature against the pool's registered verification key before accepting the vote.
3. Implement `validatePerasCert` to verify the aggregate certificate signature rather than unconditionally returning `Right`.
4. Until the above are in place, gate the ObjectDiffusion vote-ingestion path so that it does not accept votes from unauthenticated peers.

---

### Proof of Concept

**Root cause — no signature in vote type:** [1](#0-0) 

**Root cause — `validatePerasVote` only checks stake-distribution membership, no signature:** [2](#0-1) 

**Root cause — `validatePerasCert` unconditionally returns `Right`:** [3](#0-2) 

**Inbound path — `processVotes` calls `validatePerasVote` and accepts the result:** [4](#0-3) 

**Production writer — `makePerasVotePoolWriterFromChainDB` uses the broken validator:** [5](#0-4) 

**Quorum forging — accepted votes are counted and trigger certificate creation:** [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
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
