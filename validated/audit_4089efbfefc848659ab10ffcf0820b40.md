### Title
`gcHistoricityCutoff` Hardcoded to Mainnet Constants Ignores Actual Chain Parameters - (File: `ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs`)

### Summary

In `mkGenesisConfig`, the `gcHistoricityCutoff` field of `GenesisConfig` is unconditionally hardcoded to `3 * 2160 * 20 + 3600` seconds — the Shelley mainnet stability window plus one hour — regardless of the actual chain's `k`, `f`, and slot-length parameters. The `GenesisConfigFlags` record, which is the only caller-controlled input to `mkGenesisConfig`, exposes no field for overriding this value. This is the direct analog of the reported pattern: a security-critical time window is hardcoded to a constant that matches one specific configuration, while the underlying configurable parameters that determine the correct value are ignored.

### Finding Description

`mkGenesisConfig` in `Ouroboros.Consensus.Node.Genesis` sets:

```haskell
gcHistoricityCutoff = Just $ HistoricityCutoff $ 3 * 2160 * 20 + 3600
```

with the comment: *"Duration in seconds of one Cardano mainnet Shelley stability window (3k/f slots times one second per slot) plus one extra hour as a safety margin."* [1](#0-0) 

The `HistoricityCutoff` is the maximum age a `MsgRollBackward` or `MsgAwaitReply` may have at arrival time before the ChainSync client disconnects from the peer. Its specification in `HistoricityCheck.hs` states it *"should be set to at least the maximum duration (across all eras) of a stability window."* [2](#0-1) 

The actual stability window is `3·k/f` slots × slot-length seconds, where `k` (security parameter) and `f` (active slot coefficient) come from the genesis file and are fully configurable. The hardcoded expression bakes in `k = 2160`, `f = 1/20`, and `slot_length = 1 s` — Cardano mainnet Shelley values. The `GenesisConfigFlags` record has no field for `gcHistoricityCutoff`, so there is no caller-controlled path to supply the correct value for any other chain configuration. [3](#0-2) 

The enforcement in `mkCheck` is:

```haskell
when (historicityCutoff < actualRollbackAge) $ throwError HistoricityException { ... }
``` [4](#0-3) 

### Impact Explanation

**Cutoff too small (actual stability window > 133,200 s):** Any chain with a larger `k`, smaller `f`, or longer slot length has a stability window exceeding the hardcoded value. On such a chain, an honest caught-up peer whose tip slot is older than 133,200 s but still within the true stability window will trigger `HistoricityException` and be disconnected. This systematically removes honest peers from the syncing node's peer set, violating the Honest Availability Assumption (HAA) that Ouroboros Genesis requires. With the HAA unsatisfied, the Genesis Density Disconnector and Limit on Eagerness lose their security guarantees, and the syncing node can be made to prefer a non-canonical adversarial chain — a High-severity chain-selection failure reachable by any unprivileged peer on such a network.

**Cutoff too large (actual stability window < 133,200 s):** On a chain with smaller stability window (e.g., a testnet with `k=10`, `f=0.5`, 1 s slots → stability window = 60 s), the hardcoded 133,200 s cutoff is orders of magnitude too permissive. An adversarial peer can serve `MsgRollBackward` messages rewinding headers far older than the true stability window without being disconnected, bypassing the historicity guard entirely and forcing the victim to re-download large swaths of headers, defeating the ChainSync Jumping optimization and delaying convergence to the honest chain.

### Likelihood Explanation

**Low.** On Cardano mainnet the hardcoded constants are correct. The vulnerability manifests on any chain whose genesis parameters differ from mainnet Shelley values — including all testnets, private networks, and any future era that changes `k`, `f`, or slot length. The Genesis design document explicitly acknowledges this limitation: *"MaxCaughtUpAge and HistoricityCutoff are indeed constants in the implementation."* An unprivileged peer on an affected network can trigger the impact without any special capability beyond participating in ChainSync. [5](#0-4) 

### Recommendation

Derive `gcHistoricityCutoff` from the actual chain parameters rather than hardcoding mainnet constants. Concretely:

1. Add an optional `gcfHistoricityCutoff :: Maybe NominalDiffTime` field to `GenesisConfigFlags` so callers can supply the correct value.
2. Alternatively, thread the `TopLevelConfig` (which carries `k`, `f`, and slot-length via `shelleyLedgerGlobals`) into `mkGenesisConfig` and compute `HistoricityCutoff` as `max_over_eras (stabilityWindow_era × slotLength_era) + safetyMargin`, mirroring how `shelleyEraParams` derives `stabilityWindow` from `SL.computeStabilityWindow`. [6](#0-5) 

### Proof of Concept

Consider a private testnet with genesis parameters `k = 500`, `f = 0.1`, slot length = 2 s:

- True stability window = `3 × 500 / 0.1 × 2 s = 30,000 s ≈ 8.3 hours`
- Hardcoded `gcHistoricityCutoff` = `3 × 2160 × 20 + 3600 = 133,200 s ≈ 37 hours`

An adversarial peer sends a `MsgRollBackward` rewinding to a header whose slot time is 35 hours ago. The check `133,200 < (35 × 3600 = 126,000)` evaluates to **false**, so no `HistoricityException` is thrown and the peer is not disconnected, despite the rollback being far outside the true stability window. The syncing node continues to follow this adversarial peer's historical chain, stalling progress toward the honest tip.

Conversely, on a chain with `k = 3000`, `f = 1/20`, slot length = 2 s, the true stability window is `3 × 3000 × 20 × 2 = 360,000 s ≈ 100 hours`. An honest caught-up peer whose tip is 40 hours old (well within the true stability window) will be disconnected because `133,200 < (40 × 3600 = 144,000)` is **true**, incorrectly triggering `HistoricityException` and removing the honest peer from the syncing node's peer set.

### Citations

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L76-99)
```haskell
data GenesisConfigFlags = GenesisConfigFlags
  { gcfEnableCSJ :: Bool
  , gcfEnableLoEAndGDD :: Bool
  , gcfEnableLoP :: Bool
  , gcfBlockFetchGracePeriod :: Maybe DiffTime
  , gcfBucketCapacity :: Maybe Integer
  , gcfBucketRate :: Maybe Integer
  , gcfCSJJumpSize :: Maybe SlotNo
  , gcfGDDRateLimit :: Maybe DiffTime
  }
  deriving stock (Eq, Generic, Show)

defaultGenesisConfigFlags :: GenesisConfigFlags
defaultGenesisConfigFlags =
  GenesisConfigFlags
    { gcfEnableCSJ = True
    , gcfEnableLoEAndGDD = True
    , gcfEnableLoP = True
    , gcfBlockFetchGracePeriod = Nothing
    , gcfBucketCapacity = Nothing
    , gcfBucketRate = Nothing
    , gcfCSJJumpSize = Nothing
    , gcfGDDRateLimit = Nothing
    }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L108-152)
```haskell
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
mkGenesisConfig (Just cfg) =
  GenesisConfig
    { gcBlockFetchConfig =
        GenesisBlockFetchConfiguration
          { gbfcGracePeriod
          }
    , gcChainSyncLoPBucketConfig =
        if gcfEnableLoP
          then
            ChainSyncLoPBucketEnabled
              ChainSyncLoPBucketEnabledConfig
                { csbcCapacity
                , csbcRate
                }
          else ChainSyncLoPBucketDisabled
    , gcCSJConfig =
        if gcfEnableCSJ
          then
            CSJEnabled
              CSJEnabledConfig
                { csjcJumpSize
                }
          else CSJDisabled
    , gcLoEAndGDDConfig =
        if gcfEnableLoEAndGDD
          then LoEAndGDDEnabled LoEAndGDDParams{lgpGDDRateLimit}
          else LoEAndGDDDisabled
    , -- Duration in seconds of one Cardano mainnet Shelley stability window
      -- (3k/f slots times one second per slot) plus one extra hour as a
      -- safety margin.
      gcHistoricityCutoff = Just $ HistoricityCutoff $ 3 * 2160 * 20 + 3600
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/HistoricityCheck.hs (L168-180)
```haskell
  judgeRollback msg (HeaderStateWithTime headerState slotTime) = do
    arrivalTime <- systemTimeCurrent systemTime
    let actualRollbackAge = arrivalTime `diffRelTime` slotTime
    pure $
      when (historicityCutoff < actualRollbackAge) $
        throwError
          HistoricityException
            { historicalMessage = msg
            , historicalPoint = headerStatePoint headerState
            , slotTime
            , arrivalTime
            , historicityCutoff = cshc
            }
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L182-186)
```haskell
 where
  stabilityWindow =
    SL.computeStabilityWindow
      (unNonZero $ SL.sgSecurityParam genesis)
      (SL.sgActiveSlotCoeff genesis)
```
