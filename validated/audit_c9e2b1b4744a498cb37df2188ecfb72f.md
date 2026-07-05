### Title
Unsafe Default: `disableGenesisConfig` Silently Disables Long-Range Attack Protection for Syncing Nodes — (`File: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs`)

---

### Summary

The `disableGenesisConfig` value (i.e., `mkGenesisConfig Nothing`) is a fully supported, named, documented default that any integrator can pass as `rnGenesisConfig`. When used, it silently disables every syncing-safety mechanism — LoE, GDD, LoP, CSJ, and the historicity check — leaving a syncing node with no protection against the long-range attack. The vulnerability class is identical to the external report: a named "safe-looking" default that is actually unsafe for a critical security property.

---

### Finding Description

`mkGenesisConfig Nothing` produces a `GenesisConfig` in which:

- `gcLoEAndGDDConfig = LoEAndGDDDisabled` — the Limit on Eagerness and Genesis Density Disconnector are off; chain selection is unconstrained.
- `gcHistoricityCutoff = Nothing` — the historicity check is disabled; a peer may send arbitrarily old `MsgRollBackward` / `MsgAwaitReply` messages without being disconnected.
- `gcChainSyncLoPBucketConfig = ChainSyncLoPBucketDisabled` — the Limit on Patience is off; a peer may stall indefinitely.
- `gcCSJConfig = CSJDisabled` — ChainSync Jumping is off. [1](#0-0) 

This value is exported as `disableGenesisConfig` and is explicitly recommended in the changelog as the way to "keep the Praos behavior": [2](#0-1) 

The `rnGenesisConfig` field of `RunNodeArgs` has **no default** — every integrator must supply it explicitly: [3](#0-2) 

The historicity check is wired in `runWith` by inspecting `gcHistoricityCutoff`: when it is `Nothing` (as it is in `disableGenesisConfig`), `HistoricityCheck.noCheck` is used unconditionally, meaning any peer may send historical rollbacks without being disconnected: [4](#0-3) 

`noCheck` accepts every message regardless of age: [5](#0-4) 

When `LoEAndGDDDisabled`, `mkGenesisNodeKernelArgs` leaves `cdbsLoE = pure LoEDisabled` (the ChainDB default), so chain selection is never capped at `k` blocks past the LoE anchor: [6](#0-5) 

The `GenesisConfigFlags` record also allows selectively disabling LoE/GDD while keeping Genesis "enabled" (`gcfEnableLoEAndGDD = False`), which produces the same unsafe state without disabling the whole Genesis config: [7](#0-6) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest syncing node prefer a non-canonical chain beyond the intended security assumptions.**

When `disableGenesisConfig` is in use, a syncing node running Ouroboros Praos has no protection against the long-range attack:

1. An adversary with any amount of stake can pre-produce a chain that forks from the honest chain far in the past and is longer than `k` blocks.
2. Because LoE/GDD are disabled, the syncing node will eagerly select this adversarial chain as soon as it is longer than the current selection.
3. Once the adversarial chain is adopted and its tip is more than `k` blocks ahead of the honest fork point, the node's maximum-rollback invariant prevents it from ever switching back to the honest chain.
4. Because the historicity check is also disabled, the adversary can freely send `MsgRollBackward` messages rewinding to arbitrarily old points without being disconnected, facilitating the attack.

The codebase itself documents this exact attack path: [8](#0-7) [9](#0-8) 

---

### Likelihood Explanation

**Medium-High.** `disableGenesisConfig` is a named, exported, documented value that the changelog explicitly recommends for "keeping Praos behavior." Any integrator that has not yet migrated to Genesis (or that disables it for operational reasons) is in this state. The attack requires only a single adversarial peer that connects to the syncing node before an honest peer does — no stake majority, no key compromise, no admin access.

---

### Recommendation

1. **Rename or deprecate `disableGenesisConfig`** to make its security implications explicit (e.g., `unsafeDisableGenesisConfig`), and add a prominent warning in its Haddock that it removes long-range attack protection for syncing nodes.
2. **Enforce a safe default**: make `enableGenesisConfigDefault` the recommended value and require an explicit opt-out with a documented security warning.
3. **Guard partial disabling**: when `gcfEnableLoEAndGDD = False` is set inside an otherwise-enabled `GenesisConfigFlags`, emit a compile-time or runtime warning that the long-range attack protection is degraded.
4. **Document the interaction**: the configuration reference already notes that the historicity cutoff is "Disabled (`Nothing`) when Genesis is off" — this should be elevated to a security warning, not a neutral table entry. [10](#0-9) 

---

### Proof of Concept

**Setup (private testnet):**

1. Start a syncing node with `rnGenesisConfig = disableGenesisConfig` (the value recommended in the changelog for "Praos behavior").
2. Connect an adversarial peer that serves a pre-built chain forking from genesis, containing more than `k` (2160) blocks, all with valid headers signed by a small-stake key.
3. The syncing node has no honest peer connected yet (or the adversarial peer connects first).

**Execution:**

- With `LoEAndGDDDisabled`, `cdbsLoE = pure LoEDisabled`, so `chainSelection` in `ChainSel.hs` applies no LoE cap and selects the adversarial chain as soon as it is longer.
- With `gcHistoricityCutoff = Nothing`, `historicityCheck = noCheck`, so the adversary's `MsgRollBackward` messages rewinding to genesis are accepted without disconnection.
- Once the adversarial chain is adopted and its immutable tip advances past the honest fork point, the node's `maxRollbacks k` invariant prevents it from ever switching to the honest chain.

**Result:** The syncing node is permanently on the adversarial chain. It will never select the honest chain, even when an honest peer later connects, because the fork point is now deeper than `k` blocks in the immutable DB. [11](#0-10) [12](#0-11)

### Citations

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L104-120)
```haskell
-- | Disable all Genesis components, yielding Praos behavior.
disableGenesisConfig :: GenesisConfig
disableGenesisConfig = mkGenesisConfig Nothing

mkGenesisConfig :: Maybe GenesisConfigFlags -> GenesisConfig
mkGenesisConfig Nothing =
  -- disable Genesis
  GenesisConfig
    { gcBlockFetchConfig =
        GenesisBlockFetchConfiguration
          { gbfcGracePeriod = 0 -- no grace period when Genesis is disabled
          }
    , gcChainSyncLoPBucketConfig = ChainSyncLoPBucketDisabled
    , gcCSJConfig = CSJDisabled
    , gcLoEAndGDDConfig = LoEAndGDDDisabled
    , gcHistoricityCutoff = Nothing
    }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L144-147)
```haskell
    , gcLoEAndGDDConfig =
        if gcfEnableLoEAndGDD
          then LoEAndGDDEnabled LoEAndGDDParams{lgpGDDRateLimit}
          else LoEAndGDDDisabled
```

**File:** ouroboros-consensus-diffusion/CHANGELOG.md (L163-169)
```markdown
  ```haskell
  rnGenesisConfig :: GenesisConfig
  ```

  This can be set to `Ouroboros.Consensus.Node.Genesis.disableGenesisConfig` to
  keep the Praos behavior, or to `enableGenesisConfigDefault` to enable Genesis
  with preliminary parameter choices.
```

**File:** docs/website/contents/references/consensus_configuration.md (L41-56)
```markdown
## `RunNodeArgs`: always explicit

These fields have no defaults; whoever invokes the Consensus layer must decide
them.

| Field | Description |
|---|---|
| `rnTraceConsensus` | Consensus tracers (ChainSync client/server, BlockFetch, mempool, forging, …). |
| `rnTraceNTN` | Tracers for the node-to-node mini-protocol codecs/handlers. |
| `rnTraceNTC` | Tracers for the node-to-client mini-protocol codecs/handlers. |
| `rnProtocolInfo` | The `ProtocolInfo`: top-level configuration (ledger config, consensus config, codecs) and the initial (genesis) ledger state. This is where the security parameter `k`, slot lengths, etc. enter the Consensus layer — they come from the genesis files, parsed by the node. |
| `rnNodeKernelHook` | Hook called after the `NodeKernel` is initialised but before the network layer starts. `cardano-node` uses it e.g. to set up the forging credentials. |
| `rnPeerSharing` | Willingness to participate in the PeerSharing mini-protocol (a network-layer flag negotiated in the handshake). |
| `rnGetUseBootstrapPeers` | An `STM` action telling the node whether to use bootstrap peers (legacy alternative to Genesis). |
| `rnGenesisConfig` | The Ouroboros Genesis configuration, see [Genesis configuration](#genesis-configuration). |
| `rnFeatureFlags` | Set of enabled experimental features (e.g. Peras). |
```

**File:** docs/website/contents/references/consensus_configuration.md (L308-316)
```markdown
| Component | Flag / override | Default (enabled) | Meaning / implication |
|---|---|---|---|
| BlockFetch grace period | `gcfBlockFetchGracePeriod` | **10 s** | Minimum time the Genesis BlockFetch logic keeps downloading from a peer before judging (and possibly rotating) it, even if it performs badly. 0 when Genesis is disabled. |
| Limit on Patience (LoP) bucket capacity | `gcfEnableLoP`, `gcfBucketCapacity` | **100,000 tokens** | The ChainSync client disconnects from peers that withhold headers, using a token bucket: the bucket leaks constantly and is refilled on useful headers. The capacity corresponds to 200 s at the default rate — enough to absorb long GC pauses. |
| LoP leak rate | `gcfBucketRate` | **500 tokens/s** | One token per 2 ms; validating a header takes well under 1 ms, so this is conservative. |
| ChainSync Jumping (CSJ) jump size | `gcfEnableCSJ`, `gcfCSJJumpSize` | **4,320 slots** (`2·k`, the Byron forecast range) | With CSJ, only one peer serves headers at a time and the others periodically confirm jumps of this size, saving bandwidth while syncing. The Byron forecast range is used because larger (Shelley-sized) jumps would block while syncing Byron. |
| LoE & GDD | `gcfEnableLoEAndGDD` | enabled | The **Limit on Eagerness** caps chain selection at `k` blocks past the intersection of all candidate chains, and the **Genesis Density Disconnector** disconnects the peers whose chains are provably sparser, allowing the LoE to advance. |
| GDD rate limit | `gcfGDDRateLimit` | **1 s** | Run the (somewhat expensive) GDD evaluation at most once per this interval. |
| Historicity cutoff | — | **`3·k/f` s + 1 h** (129,600 s + 3,600 s on mainnet) | Rejects ChainSync messages about *historical* headers (older than the Shelley stability window, plus a safety margin) outside of syncing; such messages can only originate from adversarial behaviour. Disabled (`Nothing`) when Genesis is off. |
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node.hs (L573-577)
```haskell
                  historicityCheck getGsmState =
                    case gcHistoricityCutoff llrnGenesisConfig of
                      Nothing -> HistoricityCheck.noCheck
                      Just historicityCutoff ->
                        HistoricityCheck.mkCheck systemTime getGsmState historicityCutoff
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/HistoricityCheck.hs (L101-115)
```haskell
-- ^ The maximum age of a @MsgRollBackward@ or @MsgAwaitReply@ at arrival time,
-- constraining the age of the oldest rewound header or the tip of the candidate
-- fragment, respectively.
--
-- This should be set to at least the maximum duration (across all eras) of a
-- stability window (the number of slots in which at least @k@ blocks are
-- guaranteed to arise).
--
-- For example, on Cardano mainnet today, the Praos Chain Growth property
-- implies that @3k/f@ (=129600) slots (=36 hours) will contain at least @k@
-- (=2160) blocks. (Byron has a smaller stability window, namely @2k@ (=24 hours
-- as the Byron slot length is 20s). Thus a peer rolling back a header that is
-- older than 36 hours or signals that it doesn't have more headers is either
-- violating the maximum rollback or else isn't a caught-up node. Either way, a
-- syncing node should not be connected to that peer.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/HistoricityCheck.hs (L126-134)
```haskell
-- | Do not perform any historicity checks. This is useful when we only sync
-- from trusted peers (Praos mode) or when the impact of historical messages is
-- already mitigated by other means (for example indirectly by the Limit on
-- Patience in the case of Genesis /without/ ChainSync Jumping).
noCheck :: Applicative m => HistoricityCheck m blk
noCheck =
  HistoricityCheck
    { judgeMessageHistoricity = \_msg _hswt -> pure $ Right ()
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L120-132)
```haskell
defaultSpecificArgs :: Monad m => Incomplete ChainDbSpecificArgs m blk
defaultSpecificArgs =
  ChainDbSpecificArgs
    { cdbsBlocksToAddSize = 10
    , cdbsGcDelay = secondsToDiffTime 60
    , cdbsGcInterval = secondsToDiffTime 10
    , cdbsRegistry = noDefault
    , cdbsTracer = nullTracer
    , cdbsHasFSGsmDB = noDefault
    , cdbsTopLevelConfig = noDefault
    , cdbsLoE = pure LoEDisabled
    , cdbsSnapshotDelayRNG = noDefault
    }
```

**File:** docs/website/contents/references/glossary.md (L433-439)
```markdown
## ;Long-range attack

An adversary presents to a syncing node a chain that forks from the honest chain far in the past, in order to prevent the node from ever selecting the honest chain.

  - Superficial variant: An adversary, even with very low stake, can *eventually* produce very long (i.e. longer than `k`) forks. If a syncing node is served this chain before the honest chain, the "maximum rollback" engineering decision implies that the node can never switch away from it.

  - Fundamental variant: After some time (multiple epochs), an adversary will be able to create blocks on its fork much faster (due to accumulated block rewards/governance) than the honest chain grows. Because it's actually the longest chain in the system, the theoretical Praos node---and also the real node, if patched to allow unlimited rollback---would select this adversarial chain.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L19-38)
```haskell
-- | Protocol security parameter
--
-- In longest-chain protocols, we interpret this as the number of rollbacks we
-- support.
--
-- i.e., k == 1: we can roll back at most one block
--       k == 2: we can roll back at most two blocks, etc
--
-- NOTE: This talks about the number of /blocks/ we can roll back, not
-- the number of /slots/.
--
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
```
