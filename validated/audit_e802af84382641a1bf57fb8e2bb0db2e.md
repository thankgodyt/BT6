Let me analyze the vulnerability class from the external report and search for analogs in the Ouroboros Consensus codebase. The key pattern is: a "create X" operation fails if X already exists, and an attacker can pre-create X to block legitimate creation.

Let me look deeper at the Peras vote validation and the `PerasVoteId` type, as well as the vote validation pipeline.

Now I have enough information to write the full report. Let me verify the exact line numbers for the key code.

### Title
Peras vote pre-emption via missing signature validation permanently blocks legitimate votes and enables unauthorized certificate acceptance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types defines `PerasVote blk` without a cryptographic signature field and implements `validatePerasVote` with only a stake-distribution membership check — no BLS signature or VRF eligibility proof is verified. Because `processVotes` silently drops any incoming vote whose `PerasVoteId = (roundNo, voterId)` is already present in the `PerasVoteDB`, an unprivileged peer can pre-empt every legitimate committee member's vote by sending a structurally valid but content-forged vote first. If the attacker does this for enough committee members, quorum is reached for the attacker's chosen block instead of the honest block, a Peras certificate is forged for that block, and chain selection is permanently biased toward the attacker's chain.

---

### Finding Description

**Root cause 1 — `PerasVote blk` carries no signature**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) defines:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

There is no `pvSignature` field, no VRF eligibility proof, and no seat-index field. Any peer can construct a syntactically valid `PerasVote` for any `PerasVoterId` in the public stake distribution. [1](#0-0) 

**Root cause 2 — `validatePerasVote` performs only a stake-distribution lookup**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

The function ignores `_params` entirely and only checks whether `pvVoteVoterId` appears in the stake distribution map. No signature is verified because the `PerasVote` type carries none. [2](#0-1) 

**Root cause 3 — `processVotes` silently drops votes whose ID is already present**

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
mapM validateVote votesNotAlreadyInDb
```

`PerasVoteId` is `(pviRoundNo, pviVoterId)`. Once a vote with a given `(roundNo, voterId)` pair is in the DB — regardless of which block it targets — every subsequent vote from the same voter for the same round is silently discarded before validation. [3](#0-2) 

**Root cause 4 — `implAddVote` enforces the same one-vote-per-voter-per-round rule**

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
```

Once the attacker's forged vote occupies the `(roundNo, voterId)` slot, the legitimate vote from the real committee member is permanently excluded. [4](#0-3) 

**The `PerasVoteId` type** confirms the deduplication key is only `(roundNo, voterId)` — the voted-for block is not part of the identity check: [5](#0-4) 

---

### Impact Explanation

This is a **Critical** bypass of Peras voting and certificate checks. Because `validatePerasVote` accepts any vote whose `pvVoteVoterId` appears in the public stake distribution, an attacker can:

1. **Redirect quorum**: Forge votes for a sufficient number of committee members, all targeting the attacker's block `B'`. Each forged vote passes validation and occupies the `(roundNo, voterId)` slot in the DB.
2. **Permanently block legitimate votes**: When the real committee members' votes arrive (targeting the honest block `B`), `processVotes` silently drops them because their IDs are already present.
3. **Force certificate issuance for the wrong block**: Once the attacker's forged votes accumulate enough stake to exceed the quorum threshold, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` for `B'`.
4. **Manipulate chain selection**: The certificate for `B'` is added to the `PerasCertDB` and triggers chain selection via `chainSelSync`, boosting `B'`'s weight. An honest node may permanently prefer the attacker's chain over the canonical chain.

This matches the allowed scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

- The stake distribution (`PerasVoteStakeDistr`) is derived from the public ledger state and is available to any connected peer.
- `PerasVoterId` is a `KeyHash 'Witness` — a public key hash, observable on-chain.
- The `PerasVote` wire format encodes only `(roundNo, block, voterId)` with no signature bytes, so any peer can craft a valid-looking vote with zero cryptographic material.
- Round numbers are deterministic and predictable.
- The attacker needs only to connect via the ObjectDiffusion mini-protocol and send forged votes before the real committee members' votes propagate — a straightforward network-timing advantage for a well-connected adversary. [6](#0-5) 

---

### Recommendation

1. **Add a signature field to `PerasVote blk`** in the production instance (analogous to `pvSignature :: VoteSignature PerasBLSCrypto` already present in `Ouroboros.Consensus.Peras.Vote.V1`).
2. **Implement full signature verification in `validatePerasVote`**: verify the BLS vote signature, the VRF eligibility proof, and the seat index against the committee selection context. The BLS verification infrastructure already exists in `Ouroboros.Consensus.Peras.Crypto.BLS`.
3. **Do not rely solely on the `(roundNo, voterId)` deduplication guard** as a security boundary; it is only a performance optimization and must be backed by cryptographic authentication.

The issue is already tracked internally as `https://github.com/tweag/cardano-peras/issues/120`.

---

### Proof of Concept

```
Attacker setup:
  - Read the public stake distribution: {V1 → s1, V2 → s2, …, Vn → sn}
  - Identify round R (deterministic from slot/epoch)
  - Choose attacker-controlled block B' (e.g., tip of attacker's fork)

Attack sequence:
  1. For each Vi with sufficient cumulative stake to exceed quorum threshold:
       Construct PerasVote { pvVoteRound = R, pvVoteBlock = B', pvVoteVoterId = Vi }
       (No signature needed — the type has no signature field)

  2. Send the batch to the victim node via the ObjectDiffusion protocol.

  3. processVotes:
       - alreadyInDb is empty for round R → none filtered
       - validatePerasVote checks Vi ∈ stakeDistr → passes for all Vi
       - All forged votes are added to PerasVoteDB with IDs {(R, V1), (R, V2), …}

  4. Real committee members' votes for (R, B) arrive later:
       - processVotes filters them: (R, Vi) ∈ alreadyInDb → silently dropped

  5. updatePerasRoundVoteStates accumulates stake for B':
       - Quorum threshold exceeded → forgePerasCert produces cert for B'

  6. chainSelSync adds cert for B' to PerasCertDB and triggers chain selection:
       - B' receives Peras weight boost
       - Honest node may switch to attacker's chain
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Node/Serialisation.hs (L212-224)
```haskell
instance ConvertRawHash blk => SerialiseNodeToNode blk (PerasVote blk) where
  -- Consistent with the 'Serialise' instance for 'PerasVote' defined in Ouroboros.Consensus.Block.SupportsPeras
  encodeNodeToNode ccfg version PerasVote{..} =
    encodeListLen 3
      <> encodeNodeToNode ccfg version pvVoteRound
      <> encodeNodeToNode ccfg version pvVoteBlock
      <> encodeNodeToNode ccfg version pvVoteVoterId
  decodeNodeToNode ccfg version = do
    decodeListLenOf 3
    pvVoteRound <- decodeNodeToNode ccfg version
    pvVoteBlock <- decodeNodeToNode ccfg version
    pvVoteVoterId <- decodeNodeToNode ccfg version
    pure $ PerasVote pvVoteRound pvVoteBlock pvVoteVoterId
```
