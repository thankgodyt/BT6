### Title
Missing Cryptographic Signature Verification in `validatePerasVote` / `validatePerasCert` Allows Forged Votes and Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` and `validatePerasCert` implementations perform no cryptographic verification. Any unprivileged peer can craft `PerasVote` messages claiming any voter identity present in the public stake distribution, have them accepted by the vote-diffusion pipeline, artificially accumulate quorum stake, and force a Peras certificate to be forged for an attacker-chosen block — directly distorting chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two validation methods: `validatePerasVote` and `validatePerasCert`. The only concrete instance in the codebase is the degenerate catch-all instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

**`validatePerasCert`** unconditionally returns `Right` for every certificate it receives, performing zero validation:

```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

**`validatePerasVote`** only checks whether the claimed `pvVoteVoterId` exists in the stake distribution map. It does **not** verify any cryptographic signature or VRF eligibility proof:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [3](#0-2) 

`lookupPerasVoteStake` is a plain `Map.lookup` on the voter ID — no signature, no VRF proof, no eligibility check: [4](#0-3) 

This degenerate instance is wired directly into the production vote-diffusion pipeline. Both `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` call `validatePerasVote mkPerasParams sd vote` using this instance: [5](#0-4) 

Similarly, `makePerasVotePoolWriterFromChainDB` for certificates calls `validatePerasCert mkPerasParams`: [6](#0-5) 

The `processVotes` function deduplicates by `PerasVoteId` (a `(roundNo, voterId)` pair), so the same voter ID cannot be submitted twice per round. However, the stake distribution is public, and an attacker can craft one vote per distinct voter ID in the distribution — each with a different claimed identity — without possessing any private key: [7](#0-6) 

Once enough forged votes accumulate, `updateTargetVoteTally` sums their stakes, `votesReachQuorum` triggers, and `forgePerasCert` produces a `ValidatedPerasCert` for the attacker's chosen block — which is then added to the ChainDB and used to boost that block's chain weight in chain selection: [8](#0-7) 

The `PerasVote` wire type carries only `(pvVoteRound, pvVoteBlock, pvVoteVoterId)` — no signature field — so there is nothing for the current validator to check even if it tried: [9](#0-8) 

By contrast, the fully-implemented `WFALS` and `EveryoneVotes` committee schemes in the same codebase do verify BLS signatures and VRF proofs before accepting a vote, confirming that the degenerate instance is the missing piece: [10](#0-9) 

---

### Impact Explanation

An attacker who can connect as a peer can submit crafted `PerasVote` messages claiming the identities of legitimate high-stake voters. Because `validatePerasVote` only checks stake-distribution membership, all such votes pass validation. Once the attacker's forged votes accumulate enough stake to cross the quorum threshold, a Peras certificate is automatically forged for the attacker's chosen block. That certificate carries a `perasWeight` boost that is added to the chain weight of the attacker's block during chain selection, causing honest nodes to prefer the attacker's chain over the canonical one. This is a **bypass of Peras certificate/vote verification** enabling unauthorized certificate acceptance and a **chain selection distortion** that lets an unprivileged peer make honest nodes prefer a non-canonical chain.

---

### Likelihood Explanation

The stake distribution is public on-chain data. The `PerasVote` wire format contains no signature field in the current degenerate instance. The vote-diffusion mini-protocol is reachable by any peer. An attacker needs only to enumerate voter IDs from the stake distribution and send one crafted vote per voter ID per round. No key material, no privileged access, and no brute force is required.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote` (analogous to `WFALSPersistentVote`'s `VoteSignature` field).
2. Implement `validatePerasVote` to verify that signature against the voter's public key from the stake distribution before accepting the vote.
3. Implement `validatePerasCert` to verify the aggregate BLS signature over the claimed voter set, as done in `implVerifyCert` for `WFALS`.
4. Remove or gate the degenerate `instance StandardHash blk => BlockSupportsPeras blk` so it cannot be used in production paths.

---

### Proof of Concept

On a private testnet running the current code:

1. Observe the `PerasVoteStakeDistr` (public stake distribution) to enumerate all `PerasVoterId` values with positive stake.
2. For a target round `R` and a chosen block point `P`, craft one `PerasVote { pvVoteRound = R, pvVoteBlock = P, pvVoteVoterId = id_i }` for each high-stake voter `id_i`.
3. Send the batch to a victim node via the Peras vote diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; each passes because `lookupPerasVoteStake` finds `id_i` in the distribution.
5. `updateTargetVoteTally` accumulates the stakes; once the sum exceeds the quorum threshold, `votesReachQuorum` returns `Just`, `forgePerasCert` produces a `ValidatedPerasCert` for block `P`.
6. The certificate is added to the ChainDB; the `perasWeight` boost is applied to block `P`'s chain weight.
7. The victim node's chain selection now prefers the attacker's chosen chain over the honest canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
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
