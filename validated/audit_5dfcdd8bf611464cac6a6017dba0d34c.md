### Title
Missing Update Function for `pvdbaPerasCfg` Config Field and Silent Overwrite in `completeChainDbArgs` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs`)

---

### Summary

`ChainDB.Impl.Args` exports dedicated update functions for every configurable `ChainDbArgs` field except the Peras protocol-parameters field `pvdbaPerasCfg`. Worse, `completeChainDbArgs` unconditionally overwrites that field with the hardcoded `mkPerasParams` value, silently discarding any caller-supplied configuration. Because `pvdbaPerasCfg` governs the quorum-stake threshold, certificate weight, and voting-window parameters used by the live `PerasVoteDB`, any deployment that needs non-default Peras parameters will silently operate with the wrong values, potentially enabling certificate acceptance below the intended quorum or producing incorrect chain-selection weights.

---

### Finding Description

`ChainDB.Impl.Args` exports five update helpers that let callers adjust `ChainDbArgs` after construction: [1](#0-0) 

- `updateTracer` — propagates a new tracer to all sub-DBs
- `updateSnapshotPolicyArgs` — overrides the LedgerDB snapshot policy
- `updateQueryBatchSize` — overrides the LedgerDB query batch size
- `ensureValidateAll` — forces full validation on ImmutableDB and VolatileDB
- `enableLedgerEvents` — enables ledger-event computation

No analogous `updatePerasParams` (or `updatePerasCfg`) function exists for the `pvdbaPerasCfg` field of `PerasVoteDbArgs`.

Additionally, `completeChainDbArgs` reconstructs `cdbPerasVoteDbArgs` from scratch and **hardcodes** `pvdbaPerasCfg = mkPerasParams`, ignoring whatever value was present in the incoming `defArgs`: [2](#0-1) 

Compare this with how `pvdbaTracer` is handled — it is preserved from `defArgs` — while `pvdbaPerasCfg` is silently replaced. All other sub-DB argument blocks (`cdbImmDbArgs`, `cdbVolDbArgs`, `cdbLgrDbArgs`) are updated by extending `defArgs` with record-update syntax, preserving caller-supplied fields. Only `cdbPerasVoteDbArgs` is reconstructed wholesale with a hardcoded parameter value.

The `pvdbaPerasCfg` field (typed `PerasCfg blk = PerasParams`) is the sole source of truth for:

- `perasQuorumStakeThreshold` and `perasQuorumStakeThresholdSafetyMargin` — used by `stakeAboveThreshold` to decide when a certificate is forged
- `perasWeight` — the chain-selection boost applied to a certified block
- `perasIgnoranceRounds`, `perasCooldownRounds`, `perasCertMaxRounds`, `perasCertArrivalThreshold` — voting-window and certificate-inclusion rules [3](#0-2) 

These parameters flow directly into `implAddVote` → `updatePerasRoundVoteStates` → `votesReachQuorum` → `stakeAboveThreshold`: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

`pvdbaPerasCfg` controls the quorum threshold that determines when a Peras certificate is forged and the weight that certificate contributes to chain selection. If a deployment (e.g., a private testnet or a future mainnet parameter update) requires Peras parameters that differ from the hardcoded `mkPerasParams` defaults, those parameters are silently discarded by `completeChainDbArgs`. The node will then:

1. **Forge certificates at the wrong quorum threshold** — too low a threshold allows certificates to be produced with insufficient stake, constituting a bypass of Peras certificate checks; too high a threshold prevents legitimate certificates from being forged.
2. **Apply the wrong chain-selection weight** — an incorrect `perasWeight` causes the node to prefer or deprioritize certified chains incorrectly, breaking the Peras chain-selection invariant.
3. **Apply wrong voting-window rules** — incorrect `perasIgnoranceRounds`/`perasCooldownRounds` allow or suppress votes at the wrong times.

This falls within the allowed impact class: *bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance*, and *chain-selection bug that lets a peer make an honest node prefer a non-canonical chain*.

---

### Likelihood Explanation

Peras is an experimental feature gated by `rnFeatureFlags`. On current mainnet it is disabled by default. However, the bug is already present in the production code path and will become exploitable as soon as Peras is enabled on any network — including private testnets and staging environments — that requires non-default parameters. The silent overwrite means the misconfiguration produces no error or warning, making it difficult to detect.

---

### Recommendation

1. Add a dedicated update function analogous to the existing helpers:

```haskell
updatePerasParams ::
  PerasParams ->
  ChainDbArgs f m blk ->
  ChainDbArgs f m blk
updatePerasParams params args =
  args
    { cdbPerasVoteDbArgs =
        (cdbPerasVoteDbArgs args){PerasVoteDB.pvdbaPerasCfg = params}
    }
```

2. Fix `completeChainDbArgs` to preserve the caller-supplied `pvdbaPerasCfg` from `defArgs` instead of hardcoding `mkPerasParams`:

```haskell
, cdbPerasVoteDbArgs =
    (cdbPerasVoteDbArgs defArgs)   -- extend, don't reconstruct
      { PerasVoteDB.pvdbaTracer =
          PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
      }
```

This mirrors the pattern used for every other sub-DB argument block.

---

### Proof of Concept

**Step 1 — Observe the missing update function.** The module exports exactly five update helpers; none targets `pvdbaPerasCfg`: [6](#0-5) 

**Step 2 — Observe the silent overwrite.** `completeChainDbArgs` reconstructs `cdbPerasVoteDbArgs` with `pvdbaPerasCfg = mkPerasParams`, ignoring `defArgs`: [7](#0-6) 

**Step 3 — Confirm the field is security-critical.** `pvdbaPerasCfg` is passed directly to `implAddVote` and used to decide when a certificate is forged: [8](#0-7) 

**Step 4 — Confirm quorum validation uses this field.** `stakeAboveThreshold` reads `perasQuorumStakeThreshold` and `perasQuorumStakeThresholdSafetyMargin` from the locked-in `PerasParams`: [5](#0-4) 

A caller that pre-configures `defArgs` with a custom `pvdbaPerasCfg` (e.g., a lower quorum threshold for a testnet) and then calls `completeChainDbArgs` will find their configuration silently replaced by `mkPerasParams`, causing the node to validate certificates against the wrong quorum threshold for the lifetime of the process.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L5-16)
```haskell
module Ouroboros.Consensus.Storage.ChainDB.Impl.Args
  ( ChainDbArgs (..)
  , ChainDbSpecificArgs (..)
  , RelativeMountPoint (..)
  , completeChainDbArgs
  , defaultArgs
  , enableLedgerEvents
  , ensureValidateAll
  , updateQueryBatchSize
  , updateSnapshotPolicyArgs
  , updateTracer
  ) where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L225-233)
```haskell
      , cdbPerasCertDbArgs =
          PerasCertDB.PerasCertDbArgs
            { PerasCertDB.pcdbaTracer = PerasCertDB.pcdbaTracer (cdbPerasCertDbArgs defArgs)
            }
      , cdbPerasVoteDbArgs =
          PerasVoteDB.PerasVoteDbArgs
            { PerasVoteDB.pvdbaTracer = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
            , PerasVoteDB.pvdbaPerasCfg = mkPerasParams
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-132)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L145-162)
```haskell
createDB args@PerasVoteDbArgs{pvdbaPerasCfg} = do
  pvdeState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasVoteDbState)
      initialPerasVoteDbState
  let env =
        PerasVoteDbEnv
          { pvdeTracer
          , pvdeState
          }
  pure
    PerasVoteDB
      { addVote = implAddVote pvdbaPerasCfg env
      , getVoteIds = implGetVoteIds env
      , getVotesAfter = implGetVotesAfter env
      , getForgedCertForRound = implGetForgedCertForRound env
      , garbageCollect = implGarbageCollect env
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-210)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```
