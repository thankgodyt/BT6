### Title
Peras Vote Signature Verification Bypass Allows Unprivileged Peer to Forge Quorum and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types omits cryptographic signature verification in `validatePerasVote`. An unprivileged peer can craft `PerasVote` messages claiming to be any voter in the stake distribution, inject them via the ObjectDiffusion mini-protocol, inflate the accumulated stake toward quorum for an attacker-chosen block, trigger fraudulent certificate forging, and cause honest nodes to boost the chain weight of a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasVote` as the gate that turns a raw `PerasVote` into a `ValidatedPerasVote` carrying a stake weight. The only concrete instance in the codebase is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  data PerasVote blk = PerasVote
    { pvVoteRound   :: PerasRoundNo
    , pvVoteBlock   :: Point blk
    , pvVoteVoterId :: PerasVoterId   -- no signature field
    }
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [1](#0-0) 

The `PerasVote blk` data type carries no cryptographic signature field at all. `validatePerasVote` only calls `lookupPerasVoteStake`, which is a plain `Map.lookup` on the stake distribution keyed by `PerasVoterId`:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [2](#0-1) 

A `PerasVoterId` is a `KeyHash StakePool` — a value that is publicly visible in the ledger state. Any peer can therefore construct a `PerasVote` claiming to be any registered stake pool and it will pass validation.

The inbound path in `processVotes` (called from `makePerasVotePoolWriterFromChainDB`, the production writer) filters only by `voteId ∈ alreadyInDb` and then calls `validatePerasVote`:

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
mapM validateVote votesNotAlreadyInDb
``` [3](#0-2) 

Once a forged vote passes `validatePerasVote`, it is inserted into the `PerasVoteDB` via `implAddVote`, which calls `updatePerasRoundVoteStates` to accumulate stake:

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [4](#0-3) 

The deduplication key is `PerasVoteId = (PerasRoundNo, PerasVoterId)`. An attacker who sends one forged vote per eligible voter per round can accumulate the full stake of the committee for any block of their choosing. When `votesReachQuorum` returns `Just`, `forgePerasCert` is called — and the degenerate `forgePerasCert` also performs no real validation, unconditionally returning a `ValidatedPerasCert`:

```haskell
forgePerasCert params votes =
  return $ ValidatedPerasCert
    { vpcCert = PerasCert { pcCertRound = ..., pcCertBoostedBlock = ... }
    , vpcCertBoost = perasWeight params
    }
``` [5](#0-4) 

The resulting certificate boosts the chain weight of the attacker-chosen block by `perasWeight`, directly influencing chain selection.

---

### Impact Explanation

An unprivileged peer can cause an honest node to forge a Peras certificate for an attacker-controlled block without any legitimate votes from actual stake pool operators. The certificate carries a `perasWeight` chain-weight boost. If the boosted block is on a fork, honest nodes will prefer that fork over the canonical chain, constituting a chain selection safety failure. This matches the allowed impact: **Critical — Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance**, and **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The attack requires only:
1. Knowledge of registered `PerasVoterId` values (publicly available from the ledger state).
2. The ability to connect to a node and send `PerasVote` messages via the ObjectDiffusion mini-protocol (any peer can do this).
3. Sending one crafted vote per eligible voter per round.

No key compromise, stake majority, or privileged access is needed. The `PerasVote` type has no signature field, so there is nothing to forge cryptographically — the attacker simply fills in a known `PerasVoterId`.

---

### Recommendation

1. **Add a cryptographic signature field** to `PerasVote blk` (analogous to the concrete `PerasVote` type in `Peras.Vote.V1` which carries `pvSignature :: VoteSignature PerasBLSCrypto`).
2. **Implement real signature verification** in `validatePerasVote`, verifying the BLS signature against the voter's public key from the committee selection data before accepting the vote.
3. **Resolve the tracked issues**: `https://github.com/tweag/cardano-peras/issues/120` (non-trivial validation) and `https://github.com/tweag/cardano-peras/issues/73` (degenerate instance) before the Peras protocol is activated on any network. [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion mini-protocol
     → makePerasVotePoolWriterFromChainDB
     → processVotes (PerasVote.hs:178)
     → validatePerasVote (SupportsPeras.hs:363)  ← no signature check
     → implAddVote (Impl.hs:183)
     → updatePerasRoundVoteStates (Aggregation.hs:319)
     → votesReachQuorum (SupportsPeras.hs:242)   ← stake threshold crossed
     → forgePerasCert (SupportsPeras.hs:376)     ← certificate forged unconditionally
     → AddedPerasVoteAndGeneratedNewCert cert
     → ChainDB.addPerasVoteWithAsyncCertHandling
     → chain weight of attacker's block boosted by perasWeight
```

**Concrete steps:**

1. Query the ledger state to enumerate all `PerasVoterId` values (stake pool key hashes) and their associated `PerasVoteStake`.
2. For a target round `r` and a target block `b` (e.g., a fork tip), craft one `PerasVote { pvVoteRound = r, pvVoteBlock = b, pvVoteVoterId = v }` for each voter `v` whose cumulative stake exceeds the quorum threshold.
3. Send the batch to the victim node via the ObjectDiffusion mini-protocol.
4. `processVotes` filters out none (DB is empty for round `r`), calls `validatePerasVote` for each — all pass because each `pvVoteVoterId` is in the stake distribution.
5. Each vote is inserted; once cumulative stake crosses the threshold, `forgePerasCert` fires and the node holds a `ValidatedPerasCert` boosting block `b`.
6. Chain selection now prefers the chain containing `b` over the honest canonical chain. [7](#0-6) [8](#0-7)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L376-385)
```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-208)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```
