### Title
Peras Vote and Certificate Validation Bypass via Missing Signature Verification — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal default `BlockSupportsPeras` instance's `validatePerasVote` accepts any inbound vote claiming any voter identity without verifying the BLS signature, and `validatePerasCert` unconditionally accepts every certificate. An unprivileged NTN peer can forge votes attributed to any legitimate committee member and submit certificates that are always accepted, enabling unauthorized Peras chain boosting.

---

### Finding Description

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` defines a universal overlapping instance for all `StandardHash blk` types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

The `PerasVote blk` associated type in this instance carries only a round number, a block point, and a voter ID — **no signature field**:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [2](#0-1) 

The `validatePerasVote` implementation only checks whether the claimed voter's stake exists in the stake distribution. It performs **no cryptographic verification** of who actually sent the vote:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [3](#0-2) 

`validatePerasCert` is even more permissive — it **always returns `Right`** regardless of the certificate content:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [4](#0-3) 

This default instance is the one consumed by the production inbound vote processing path. `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote` directly via the `BlockSupportsPeras` class:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
``` [5](#0-4) 

The `processVotes` function then passes each vote through this validation callback and, if it passes, timestamps and stores it via `addPerasVoteWithAsyncCertHandling`: [6](#0-5) 

The concrete `PerasVote` type in `Ouroboros.Consensus.Peras.Vote.V1` does carry a `pvSignature` field and the `WFALS`/`EveryoneVotes` committee implementations do verify signatures properly — but those are `CryptoSupportsVotingCommittee` implementations, not `BlockSupportsPeras` instances. No concrete `BlockSupportsPeras` override that wires in signature verification is present in the codebase; the universal stub is what is dispatched. [7](#0-6) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras vote and certificate verification.**

Because `validatePerasVote` accepts any vote whose claimed `PerasVoterId` appears in the stake distribution, an attacker can:

1. Observe the current `PerasVoteStakeDistr` (publicly derivable from the ledger state).
2. Craft `PerasVote` messages claiming to be any high-stake committee member.
3. Submit enough forged votes to satisfy `votesReachQuorum`, which only checks total stake and target agreement — not signatures. [8](#0-7) 

4. Trigger `addPerasVoteWithAsyncCertHandling`, which may forge a `PerasCert` for the attacker-chosen block.
5. Because `validatePerasCert` always returns `Right`, any certificate the attacker submits directly is also accepted unconditionally.

The result is that the attacker can boost an arbitrary block — including a non-canonical or adversarially-chosen one — causing the victim node to prefer a chain that would otherwise lose chain selection. This is a direct bypass of the Peras voting/certificate authorization mechanism.

---

### Likelihood Explanation

**Likelihood: High.**

- The entry point is the standard NTN object-diffusion mini-protocol, reachable by any unprivileged peer.
- No keys, stake, or privileged access are required; only knowledge of the current stake distribution (public ledger data).
- The attack requires crafting a small number of `PerasVote` CBOR messages with a valid `PerasVoterId` and a target block point — trivially constructable.
- The TODO comments confirm this is a known incomplete stub, not a deliberate design choice, making it likely to be present in any deployment that activates Peras.

---

### Recommendation

1. **Add a signature field to the default `PerasVote blk` associated type**, or remove the universal default instance and require each concrete block type to provide a verified implementation.
2. **`validatePerasVote` must verify the BLS vote signature** against the voter's public key from the stake distribution before accepting the vote, mirroring the pattern already implemented in `WFALS.implVerifyVote` and `EveryoneVotes.implVerifyVote`.
3. **`validatePerasCert` must verify the aggregate BLS signature** over the certificate's claimed voters, mirroring `WFALS.implVerifyCert`.
4. Track and close [cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120) and [cardano-peras#73](https://github.com/tweag/cardano-peras/issues/73) before any Peras-enabled deployment.

---

### Proof of Concept

**Attacker preconditions:** NTN peer connection to a victim node running a Peras-enabled build; read access to the current ledger state (public).

**Steps:**

1. Query the victim node's ledger state to obtain `PerasVoteStakeDistr` and identify a committee member `vid` with stake above the quorum threshold.
2. Choose a target block `blk` to boost (e.g., the attacker's own fork tip).
3. Construct a `PerasVote` CBOR message:
   ```
   PerasVote { pvVoteRound = <current_round>, pvVoteBlock = blk, pvVoteVoterId = vid }
   ```
   No signing key for `vid` is needed.
4. Send this vote over the NTN object-diffusion protocol to the victim node.
5. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; since `lookupPerasVoteStake vote sd` returns `Just stake` for the legitimate `vid`, the vote is accepted as `ValidatedPerasVote { vpvVoteStake = <victim's stake> }`.
6. If the attacker submits enough such forged votes (or a single vote from a majority-stake member), `votesReachQuorum` returns `Just`, a `PerasCert` is forged for `blk`, and the victim node boosts the attacker's chosen block.
7. Alternatively, submit a crafted `PerasCert` directly; `validatePerasCert` returns `Right` unconditionally, so the certificate is accepted without any verification. [9](#0-8) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-270)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-180)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
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
