### Title
Peras vote validation stub accepts unauthenticated votes for arbitrary rounds, enabling unauthorized certificate forging and chain-selection manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation is an explicit TODO stub that only checks stake-distribution membership. The `PerasVote` type carries no cryptographic signature field, and no round-number or target-block binding is verified. Any unprivileged peer can craft votes claiming to be from any voter in the public stake distribution, for any round and any block. When enough such crafted votes accumulate to quorum, a `ValidatedPerasCert` is forged, stored in `PerasCertDB`, and used to boost a fork block in chain selection, potentially causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasVote` stub:**

The `BlockSupportsPeras` type class defines `validatePerasVote` as the sole validation gate for inbound votes. The only production instance (a catch-all `instance StandardHash blk => BlockSupportsPeras blk`) is explicitly marked as a TODO stub:

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

The check is purely `lookupPerasVoteStake vote stakeDistr` — a `Map.lookup` on `pvVoteVoterId`. It does **not** verify:
1. Whether `pvVoteRound` corresponds to the current Peras round (no round-number binding)
2. Whether `pvVoteBlock` is on the current chain
3. Any cryptographic signature — the `PerasVote` type has no signature field at all:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound :: PerasRoundNo
  , pvVoteBlock :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [2](#0-1) 

**`validatePerasCert` is also a stub that accepts every certificate unconditionally:**

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [3](#0-2) 

**Production inbound path — `processVotes`:**

`validatePerasVote` is called in the production diffusion path. `processVotes` filters already-known votes, calls `validateVote` (which resolves to `validatePerasVote`), and on success adds each vote to the database:

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  ...
``` [4](#0-3) 

This is wired into both `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB`, the production inbound vote handlers: [5](#0-4) 

**Vote storage — `implAddVote`:**

Accepted votes are stored in `PerasVoteDB`. Deduplication is by `PerasVoteId = (roundNo, voterId)`, so each `(round, voter)` pair is stored once. When accumulated stake for a `(round, block)` target crosses the quorum threshold, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert`: [6](#0-5) 

The forged certificate is then added to `PerasCertDB` via `addPerasCertAsync`, which updates `getPerasWeightSnapshot` and triggers chain selection re-evaluation. [7](#0-6) 

**Analog to the external report:**

| External report (Swafe) | Ouroboros Consensus |
|---|---|
| `GuardianShare` passes `backup.verify` (session-agnostic signature check) | `PerasVote` passes `lookupPerasVoteStake` (voter-identity check only) |
| Missing: binding to current `recovery_pke` session | Missing: binding to current Peras round number and cryptographic signature |
| Storage key `(account_id, backup_id, share_id)` lacks session ID | `PerasVoteId = (roundNo, voterId)` includes round but round is never validated against current round |
| Old-session shares corrupt new-session recovery | Crafted votes for arbitrary rounds forge certificates that corrupt chain selection |

---

### Impact Explanation

An unprivileged peer can:

1. Observe the public stake distribution to enumerate valid `PerasVoterId` values (V₁…Vₖ).
2. Craft `PerasVote { pvVoteRound = R, pvVoteBlock = forkBlock, pvVoteVoterId = Vᵢ }` for i = 1…k, where `forkBlock` is a block on a competing fork and k is chosen so that the total stake of V₁…Vₖ exceeds the quorum threshold.
3. Send these votes via the Peras vote diffusion protocol.
4. `processVotes` calls `validatePerasVote` for each; all pass because each Vᵢ is in the stake distribution.
5. `implAddVote` stores each vote; when quorum is reached, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` for `(R, forkBlock)`.
6. The certificate is added to `PerasCertDB` and boosts `forkBlock` in `getPerasWeightSnapshot`.
7. Chain selection re-runs and may switch to the fork containing `forkBlock`.

This is a **Critical** bypass of Peras voting checks enabling unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer.

---

### Likelihood Explanation

The stake distribution is public ledger state. Any peer connected to the node can send `PerasVote` messages via the object-diffusion mini-protocol. No key compromise, no stake majority, and no special privilege is required. The attacker only needs to read the public stake distribution and send enough crafted votes to reach quorum. The attack is repeatable across rounds.

---

### Recommendation

1. **Add cryptographic signatures to `PerasVote`**: introduce a `pvVoteSignature` field and verify it against the voter's registered key in `validatePerasVote`.
2. **Enforce round-number binding**: reject votes whose `pvVoteRound` does not correspond to the current Peras round (derivable from the current slot via `perasRoundNoToSlot`).
3. **Enforce target-block validity**: reject votes whose `pvVoteBlock` is not on the node's current chain or is older than the candidate slot horizon.
4. **Implement `validatePerasCert`**: verify certificate authenticity (signatures from a quorum of committee members) rather than accepting every certificate unconditionally.
5. Track the referenced GitHub issue (`cardano-peras/issues/120`) as a security-critical blocker before Peras is enabled on any production network.

---

### Proof of Concept

```
1. Attacker reads the public PerasVoteStakeDistr from the ledger state.
   Identifies voter IDs V1, V2, ..., Vk with combined stake > quorum threshold.

2. Attacker selects a fork block F (e.g., a block on a competing chain).

3. Attacker crafts k PerasVote messages:
     vote_i = PerasVote { pvVoteRound = R, pvVoteBlock = F, pvVoteVoterId = V_i }
   for i = 1..k, where R is any round number.

4. Attacker sends vote_1..vote_k to the target node via the Peras vote
   diffusion mini-protocol.

5. processVotes calls validatePerasVote for each vote_i.
   Each passes: lookupPerasVoteStake finds V_i in the stake distribution.

6. implAddVote stores each vote. When the k-th vote is added,
   updatePerasRoundVoteStates detects quorum for (R, F) and forges:
     cert = ValidatedPerasCert { vpcCert = PerasCert { pcCertRound = R,
                                                       pcCertBoostedBlock = F },
                                 vpcCertBoost = perasWeight params }

7. addPerasCertAsync stores cert in PerasCertDB and triggers chain selection.

8. getPerasWeightSnapshot now includes a boost for F.
   Chain selection may switch to the fork containing F.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-246)
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

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
