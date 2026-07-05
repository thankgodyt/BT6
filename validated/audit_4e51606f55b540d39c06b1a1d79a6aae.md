### Title
Peras Vote and Certificate Validation Bypass via Stub `BlockSupportsPeras` Instance Enables Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production catch-all `BlockSupportsPeras` instance used for all block types performs no cryptographic verification of inbound Peras votes or certificates. `validatePerasCert` unconditionally accepts every certificate, and `validatePerasVote` only checks that a voter ID exists in the public stake distribution — it never verifies a signature because the stub `PerasVote` data type carries no signature field at all. Any unprivileged peer connected via the ObjectDiffusion miniprotocol can therefore inject forged votes for any eligible pool key, accumulate a fraudulent quorum, and cause the node to generate and accept a certificate that boosts a non-canonical chain, triggering a chain-selection switch.

---

### Finding Description

**Root cause — stub instance is the only production instance**

The `BlockSupportsPeras` typeclass is the sole interface through which inbound Peras votes and certificates are validated before being stored and acted upon. The repository contains exactly one instance, explicitly marked as a degenerate placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Because no more-specific instance exists for `CardanoBlock`, `ShelleyBlock`, or any other concrete block type, this stub is the instance resolved at every call site in production.

**`validatePerasCert` — unconditional acceptance**

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
``` [2](#0-1) 

Every certificate received from any peer is immediately wrapped in `ValidatedPerasCert` with a boost of `PerasWeight 15` (from `mkPerasParams`). No round-number range check, no aggregate-signature verification, no quorum proof — nothing.

**`validatePerasVote` — no signature field, no signature check**

The stub `PerasVote` data type carries only a round number, a block point, and a voter ID:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [3](#0-2) 

There is no signature field. Validation therefore reduces to a single map lookup:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

Any peer who knows a pool key hash that appears in the public stake distribution can forge a vote for that pool without possessing the corresponding private key.

**Inbound path — ObjectDiffusion miniprotocol writers**

Both pool writers that handle peer-provided objects call the stub validators directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [5](#0-4) 

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [6](#0-5) 

**Chain-selection consequence**

Once a certificate is accepted, `addPerasCertAsync` enqueues it for `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [7](#0-6) 

Chain comparison uses `WeightedSelectView`, where `wsvTotalWeight = BlockNo + wsvWeightBoost`. A fraudulent certificate adds `PerasWeight 15` to the boosted fork's weight, which can flip the chain-selection decision:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [8](#0-7) 

---

### Impact Explanation

**Severity: Critical — Bypass of Peras voting and certificate checks enabling unauthorized chain weight manipulation.**

An unprivileged peer can:

1. **Direct certificate injection**: Send a single `PerasCert` for any block in the VolatileDB. `validatePerasCert` accepts it unconditionally. The node immediately re-runs chain selection with the boosted fork, potentially switching away from the canonical chain.

2. **Vote-accumulation path**: Send forged `PerasVote` objects for distinct pool key hashes drawn from the public stake distribution (no private keys required). Once the accumulated `PerasVoteStake` exceeds the quorum threshold (75% + 2% safety margin), `addPerasVoteWithAsyncCertHandling` internally calls `forgePerasCert` and then `addPerasCertAsync`, triggering the same chain-selection switch.

Both paths result in a node accepting an unauthorized Peras certificate and potentially adopting a non-canonical chain, constituting a consensus safety failure reachable by any peer on a Peras-enabled network.

---

### Likelihood Explanation

**High.** The attack requires only:
- A TCP connection to a node with Peras enabled (the ObjectDiffusion miniprotocol is the standard peer-to-peer channel).
- Knowledge of pool key hashes in the current stake distribution — this is public on-chain data.
- No private keys, no stake, no special privileges.

The `PerasVote` serialisation format is fully specified and stable (CBOR, 3-field list), making crafted vote construction trivial. The quorum threshold of 77% of total stake is achievable by sending votes attributed to the largest pools, whose key hashes are publicly known.

---

### Recommendation

1. **Immediate**: Gate the ObjectDiffusion miniprotocol handlers so that inbound votes and certificates are rejected with a hard error until real cryptographic validation is implemented. The existing `TODO` comments reference `https://github.com/tweag/cardano-peras/issues/120` and `https://github.com/tweag/cardano-peras/issues/73`; these must be resolved before Peras is enabled on any network that processes real value.

2. **Short term**: Replace the degenerate `instance StandardHash blk => BlockSupportsPeras blk` with a proper instance for `CardanoBlock` (or the relevant concrete type) that verifies BLS aggregate signatures on certificates and individual BLS/VRF signatures on votes, as implemented in the `EveryoneVotes` committee (`implVerifyVote`) and the `V1` vote type (`PerasVoteEligibilityProof`).

3. **Long term**: Enforce at the type level that a `ValidatedPerasCert` or `ValidatedPerasVote` can only be constructed by the real validation functions, not by the stub instance. Consider making the `BlockSupportsPeras` class an `error`-guarded stub rather than a silently-accepting one, so any accidental use in production is caught at runtime rather than silently accepted.

---

### Proof of Concept

**Preconditions**: A Cardano node with `PerasSupport` enabled (private testnet or future mainnet). The attacker has a standard peer-to-peer connection.

**Step 1 — Obtain public pool key hashes** from the ledger state (e.g., via a node-to-client query). These are the `PerasVoterId` values.

**Step 2 — Identify a target block** in the peer's VolatileDB (e.g., a block on a competing fork one block behind the current tip).

**Step 3 — Forge votes** by constructing `PerasVote` CBOR objects:
```
[roundNo, blockPoint, poolKeyHash_i]
```
for each of the top-stake pool key hashes until their combined `PerasVoteStake` exceeds 77% of total stake. No signatures are required because the stub `PerasVote` type has no signature field.

**Step 4 — Send votes** via the ObjectDiffusion miniprotocol. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; all pass because the voter IDs are in the stake distribution.

**Step 5 — Quorum triggers certificate generation**: `addPerasVoteWithAsyncCertHandling` detects quorum, calls `forgePerasCert`, and enqueues the resulting `ValidatedPerasCert` via `addPerasCertAsync`.

**Step 6 — Chain selection fires**: `chainSelSync` processes the certificate, adds `PerasWeight 15` to the target block's fork weight, and calls `chainSelectionForBlock`. If the fork's `BlockNo + 15` exceeds the current tip's `BlockNo`, the node switches to the non-canonical chain.

**Alternative (direct certificate injection)**: Skip steps 3–5 entirely. Send a single `PerasCert` CBOR object directly via the ObjectDiffusion cert miniprotocol. `validatePerasCert mkPerasParams cert` returns `Right` unconditionally, and the chain-selection switch fires immediately.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L531-531)
```haskell
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
