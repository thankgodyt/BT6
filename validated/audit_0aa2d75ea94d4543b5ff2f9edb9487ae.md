### Title
Peras Vote Voter Identity Not Cryptographically Validated, Enabling Fraudulent Quorum and Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in `SupportsPeras.hs` accepts a `PerasVote` as valid if and only if the `pvVoteVoterId` field resolves to an entry in the stake distribution. No cryptographic signature is verified. Because the `PerasVote` data type carries no signature field at all, any unprivileged peer can craft a vote claiming to be from any eligible pool ID, accumulate enough fraudulent stake weight to satisfy the quorum threshold, and cause the node to accept a forged Peras certificate that boosts an attacker-chosen block in chain selection.

---

### Finding Description

The `PerasVote` struct (the default `BlockSupportsPeras` instance) is defined as:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- just a KeyHash StakePool
  }
``` [1](#0-0) 

There is no signature field. The entire validation performed on a network-received vote is:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` only performs a `Map.lookup` on `pvVoteVoterId`:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [3](#0-2) 

There is no check that the sender possesses the private key corresponding to the claimed pool ID. The `pvVoteVoterId` field is accepted as-is, exactly as the `proposer` address in the original report's `Dispute` struct was accepted without validation.

The same stub is used for `validatePerasCert`, which unconditionally returns `Right` for every certificate received:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [4](#0-3) 

Both stubs are wired into the production inbound processing paths. `makePerasVotePoolWriterFromChainDB` (the path used when the ChainDB handles cert side-effects) calls `validatePerasVote mkPerasParams sd vote` directly: [5](#0-4) 

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` directly: [6](#0-5) 

No other `BlockSupportsPeras` instance exists in production code; the only overrides are in test files. [7](#0-6) 

---

### Impact Explanation

Peras certificates grant a configurable weight boost (`perasWeight`) to the block they reference during chain selection. A node that accepts a fraudulent certificate will prefer the boosted block over a legitimately longer chain, constituting a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain** beyond the intended security assumptions.

Concretely:
1. An attacker forges enough votes (each claiming a different eligible pool ID) to satisfy `votesReachQuorum`. Because `validatePerasVote` only checks stake-distribution membership, every forged vote passes.
2. The `PerasVoteDB` accumulates these votes and, once quorum is reached, calls `forgePerasCert` to produce a certificate.
3. The certificate is stored and applied to chain selection, boosting the attacker's chosen block.
4. Separately, the attacker can also directly inject a forged `PerasCert` via the cert diffusion path; `validatePerasCert` accepts it unconditionally.

This maps to the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The attack requires only the ability to send well-formed CBOR-encoded `PerasVote` or `PerasCert` messages over the object-diffusion mini-protocol — no keys, no stake, no privileged access. Any peer that can establish a connection can exploit this. Likelihood is **High** once Peras is active on a network running this code.

---

### Recommendation

**Short term**: Add a cryptographic signature field to `PerasVote` (analogous to how `BHBody` carries an `OCert` and a KES signature). `validatePerasVote` must verify that the signature over `(pvVoteRound, pvVoteBlock)` is valid under the public key associated with `pvVoteVoterId` in the stake distribution before accepting the vote.

**Long term**: Replace the degenerate `instance StandardHash blk => BlockSupportsPeras blk` stub with a proper era-specific instance (as is done for Praos via `ProtocolHeaderSupportsProtocol`). Enforce at the type level that no production code path can call `validatePerasVote` or `validatePerasCert` without a real implementation in scope. Add adversarial property tests that submit votes with mismatched voter IDs and forged certificates, asserting they are rejected.

---

### Proof of Concept

1. Observe the stake distribution to enumerate pool IDs with positive stake.
2. For a target block `B` in round `R`, craft `N` `PerasVote` messages:
   ```
   PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = poolId_i }
   ```
   for `i = 1..N`, choosing pool IDs whose combined stake exceeds the quorum threshold.
3. Send these votes to the victim node via the object-diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; each passes because `lookupPerasVoteStake` finds the pool ID in the distribution.
5. `votesReachQuorum` returns `Just` once total stake exceeds the threshold.
6. `forgePerasCert` produces a `ValidatedPerasCert` boosting block `B`.
7. Chain selection now prefers any chain whose tip is `B` over a legitimately longer chain, causing the node to diverge from the honest chain. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-200)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
