### Title
Peras Vote Signature Verification Bypass Allows Forged Votes from Unprivileged Peers - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasVote` implementation omits all cryptographic signature verification. It accepts any vote from a registered voter without checking a BLS signature. An unprivileged peer connected via the object diffusion miniprotocol can forge Peras votes for any registered stake pool, accumulate false quorum, and cause an invalid `ValidatedPerasCert` to be generated and applied to chain selection.

---

### Finding Description

The `validatePerasVote` method in the default `BlockSupportsPeras` instance performs only a stake-distribution membership lookup:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

The `PerasVote blk` data type in this same instance carries no signature field at all — only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId`: [2](#0-1) 

This stub is the implementation invoked by `processVotes` in the inbound vote-processing path:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

`processVotes` receives votes from remote peers, filters out already-known vote IDs, then calls `validateVote` on the remainder. Because `validatePerasVote` only checks stake-distribution membership, any peer can craft a `PerasVote` with an arbitrary `pvVoteVoterId` (any registered pool key hash) and any `pvVoteRound`/`pvVoteBlock` and it will be accepted as valid: [4](#0-3) 

The `PerasVoteId` used for deduplication is `(roundNo, voterId)`: [5](#0-4) 

So one forged vote per `(round, voter)` pair passes deduplication and validation. With enough forged votes the `PerasVoteDB` reaches quorum and `forgePerasCert` is called, producing a `ValidatedPerasCert` that is then inserted into the `ChainDB` via `addPerasVoteWithAsyncCertHandling`: [6](#0-5) 

The concrete `V1.PerasVote` type and the `WFALS` committee (`implVerifyVote`) already contain the correct BLS signature verification infrastructure, but it is never wired into the production `validatePerasVote` path: [7](#0-6) 

The TODO comment in the source explicitly acknowledges the gap: [8](#0-7) 

---

### Impact Explanation

A `ValidatedPerasCert` produced from forged votes is indistinguishable from a legitimate one inside the `ChainDB`. Peras certificates boost the chain-selection weight of the boosted block by `perasWeight`: [9](#0-8) 

An attacker who submits enough forged votes to reach quorum causes honest nodes to prefer a non-canonical chain, constituting a **bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance** — matching the Critical impact tier.

---

### Likelihood Explanation

The stake distribution is public on-chain information. Any peer connected via the object diffusion miniprotocol can enumerate registered pool key hashes and submit one forged `PerasVote` per `(round, pool)` pair. No key material is required. The only barrier is knowing which pools are registered, which is trivially observable.

---

### Recommendation

Wire the existing BLS signature verification from `implVerifyVote` / `verifyVoteSignature` into the production `validatePerasVote` implementation. The concrete `V1.PerasVote` type already carries `pvSignature` and `pvSeatIndex`; the `WFALS` committee already implements `implVerifyVote` correctly. The default `BlockSupportsPeras` instance must be replaced with an implementation that:

1. Deserialises the vote as a `V1.PerasVote` (or equivalent).
2. Calls `fromPerasVote` to obtain a `Vote PerasBLSCrypto WFALS`.
3. Calls `implVerifyVote committee vote` to verify the BLS signature and VRF eligibility proof before accepting the vote.

---

### Proof of Concept

1. Connect to a target node via the object diffusion miniprotocol (vote diffusion channel).
2. Query the current stake distribution to enumerate registered `PerasVoterId` key hashes.
3. For each pool key hash `v_i` with sufficient stake, craft:
   ```
   PerasVote { pvVoteRound = currentRound
             , pvVoteBlock = targetBlock
             , pvVoteVoterId = v_i }
   ```
   No signing key is needed; the `PerasVote blk` type carries no signature field.
4. Submit the batch. `processVotes` filters by `PerasVoteId` (round, voter) — each forged vote is new, so none are skipped.
5. `validatePerasVote` checks only `lookupPerasVoteStake vote stakeDistr` — all votes pass.
6. Once cumulative `vpvVoteStake` exceeds `perasQuorumStakeThreshold + safetyMargin`, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a `ValidatedPerasCert` for `targetBlock`.
7. The certificate is inserted into the `ChainDB` via `addPerasVoteWithAsyncCertHandling`, boosting `targetBlock`'s chain-selection weight and potentially causing honest nodes to switch to the attacker-chosen chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-352)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-211)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
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
