### Title
`BlockSupportsPeras::validatePerasVote` Never Checks BLS Signature or VRF Eligibility Proof, Enabling Fraudulent Peras Certificate Forging - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function — the sole gate that decides whether a network-received Peras vote is accepted — never verifies the BLS vote signature or the VRF eligibility proof. Any unprivileged peer can craft a `PerasVote` message that names any registered stake pool as the voter, and the node will accept it as a `ValidatedPerasVote`, count its full stake weight toward quorum, and — once enough such forged votes accumulate — automatically forge a fraudulent Peras certificate that boosts an attacker-chosen block in chain selection.

---

### Finding Description

`BlockSupportsPeras` defines `validatePerasVote` as the authorization gate for inbound votes. The production implementation (the only one in the codebase, confirmed by `grep`) is the universal instance at `SupportsPeras.hs:320`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The `_params` argument (the Peras configuration, which carries the cryptographic context) is **discarded** (note the leading underscore). The only check performed is a stake-distribution lookup by voter ID. No BLS signature over `(roundNo, boostedBlock)` is verified. No VRF eligibility proof for non-persistent committee members is checked. The `PerasVote` data type for this instance (`pvVoteRound`, `pvVoteBlock`, `pvVoteVoterId`) carries no signature field at all, so there is nothing to verify even if the code tried.

The same pattern applies to `validatePerasCert`, which unconditionally wraps any certificate in `Right` without checking the aggregate BLS signature.

The network ingestion path in `processVotes` calls exactly this function:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` use this call site. There is no other `validatePerasVote` definition in the repository — the `grep` search returns only `SupportsPeras.hs` (definition) and `ObjectPool/PerasVote.hs` (two call sites).

The `implAddVote` function in `PerasVoteDB/Impl.hs` carries a matching TODO:

```
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

---

### Impact Explanation

**Critical — Bypass of Peras vote/certificate signature validation enabling unauthorized certificate acceptance.**

Once a fraudulent `ValidatedPerasCert` is forged from attacker-supplied votes, it is handed to `ChainDB.addPerasVoteWithAsyncCertHandling`. Peras certificates provide a configurable `perasWeight` boost to chain selection (`vpcCertBoost`). A node that holds a fraudulent certificate for an attacker-chosen block will prefer that block's chain over the honest canonical chain, constituting a chain-selection safety failure driven entirely by network input from an unprivileged peer.

The attacker needs only to know the `PerasVoterId` (stake pool key hash) of enough registered pools to exceed the quorum threshold — all of which are public on-chain data. No key material is required.

---

### Likelihood Explanation

**High.** The attack requires only:
1. Knowledge of registered stake pool key hashes (public on-chain).
2. The ability to send `PerasVote` messages via the object-diffusion mini-protocol (any peer connection).
3. Sending enough forged votes to exceed the quorum threshold.

No cryptographic secrets, no stake majority, no operator compromise. The TODO comments and the referenced issue (`cardano-peras/issues/120`) confirm the developers are aware the validation is a placeholder, not a deliberate design choice.

---

### Recommendation

`validatePerasVote` must verify:
1. The BLS vote signature over `(roundNo, boostedBlock)` using the voter's registered BLS verification key.
2. For non-persistent committee members: the VRF eligibility proof against the epoch nonce and round number.
3. That the voter's seat index corresponds to a legitimate committee member for the given round.

`validatePerasCert` must verify the aggregate BLS signature over all claimed voters before accepting any certificate.

The `_params` argument to `validatePerasVote` must be used (not discarded) to supply the cryptographic context for these checks. The `PerasVote` data type for the production instance must be extended to carry a signature field, mirroring the `V1.PerasVote` type in `Peras/Vote/V1.hs` which already includes `pvSignature` and `pvEligibilityProof`.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects and sends a batch of `PerasVote` objects via the object-diffusion mini-protocol.
2. `processVotes` filters already-seen votes, then calls `validatePerasVote mkPerasParams sd vote` for each new vote.
3. `validatePerasVote` performs only `lookupPerasVoteStake vote stakeDistr` — a map lookup by `pvVoteVoterId`.
4. For any voter ID present in the stake distribution (all public), the vote is accepted as `ValidatedPerasVote` with the full registered stake weight.
5. `implAddVote` calls `updatePerasRoundVoteStates`, which accumulates stake. Once the quorum threshold is crossed, `forgePerasCert` is called and a `ValidatedPerasCert` is produced.
6. The certificate is submitted to `ChainDB.addPerasVoteWithAsyncCertHandling`, boosting the attacker's chosen block in chain selection.

**Minimal reproducer sketch (private testnet):**

```haskell
-- Craft a vote for any registered pool, for any block point
let forgedVote = PerasVote
      { pvVoteRound  = currentRound
      , pvVoteBlock  = targetBlockPoint   -- attacker-chosen
      , pvVoteVoterId = knownPoolKeyHash  -- from on-chain stake distribution
      }
-- Send via object-diffusion protocol; no signature needed
-- Repeat for enough pools to exceed quorum threshold
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-113)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
