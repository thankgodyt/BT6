### Title
Hardcoded `HistoricityCutoff` Constant Encodes Mainnet-Specific Protocol Parameters, Breaking Genesis Peer-Disconnection Logic if Stability Window Grows - (File: `ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs`)

---

### Summary

`mkGenesisConfig` in `Genesis.hs` hardcodes the `HistoricityCutoff` as the literal expression `3 * 2160 * 20 + 3600` seconds (37 hours). This bakes in three mainnet-specific constants — `k = 2160`, `1/f = 20` (active-slot coefficient `f = 0.05`), and a 1-second slot length — rather than computing the value from the actual runtime protocol parameters. The `HistoricityCutoff` is the sole guard that the ChainSync client uses to disconnect peers that send `MsgRollBackward` or `MsgAwaitReply` messages referencing headers older than the stability window. If the Cardano stability window (`Scg = 3k/f` slots × slot-length) ever exceeds 37 hours — through any hard fork that raises `k` or lowers `f` — the hardcoded constant becomes smaller than the true `Scg`. An honest caught-up peer that legitimately rolls back within the new stability window will be disconnected as if it were adversarial, collapsing the Honest Availability Assumption (HAA) that underpins all of Ouroboros Genesis's safety guarantees.

---

### Finding Description

**Root cause — `mkGenesisConfig`, line 151:**

```haskell
-- Duration in seconds of one Cardano mainnet Shelley stability window
-- (3k/f slots times one second per slot) plus one extra hour as a
-- safety margin.
gcHistoricityCutoff = Just $ HistoricityCutoff $ 3 * 2160 * 20 + 3600
``` [1](#0-0) 

The `HistoricityCutoff` type's own documentation states the invariant that must hold:

> "This should be set to at least the maximum duration (across all eras) of a stability window." [2](#0-1) 

The enforcement logic in `mkCheck` compares the hardcoded cutoff against the real wall-clock age of the rolled-back header:

```haskell
let actualRollbackAge = arrivalTime `diffRelTime` slotTime
pure $
  when (historicityCutoff < actualRollbackAge) $
    throwError HistoricityException { … }
``` [3](#0-2) 

The check fires in both `PreSyncing` and `Syncing` GSM states — exactly the states where Genesis security matters — and is disabled only in `CaughtUp`: [4](#0-3) 

The `historicityCutoff` passed to `mkCheck` comes directly from `gcHistoricityCutoff` in the `GenesisConfig`, which is always the hardcoded literal when Genesis is enabled: [5](#0-4) 

The design document explicitly acknowledges the fragility:

> "HistoricityCutoff = 36+1 hours. This value must be greater than Scg of the Cardano chain's current era, which is 36 hours, and will remain so for the foreseeable future. It seems very unlikely that the community will increase the upper bound on settlement time, but if they did, then HistoricityCutoff would need to increase accordingly."
> "One caveat: MaxCaughtUpAge and HistoricityCutoff are indeed constants in the implementation, but Sgen is actually implemented to vary as the chain transitions eras." [6](#0-5) [7](#0-6) 

Unlike `Sgen` (the GDD window), which is already implemented to vary dynamically across eras, `HistoricityCutoff` has no such dynamic path. The `GenesisConfigFlags` record exposes no field for it, so there is no operator override either. [8](#0-7) 

---

### Impact Explanation

The `HistoricityCutoff` is the boundary condition that separates "honest caught-up peer" from "adversarial or stale peer" in the Genesis ChainSync client. Its correctness is a **necessary precondition** for the Honest Availability Assumption (HAA). The HAA is in turn the foundation of every Genesis safety theorem: without it, a syncing node has no guarantee that any of its peers is honest, and the long-range attack that Genesis was designed to prevent becomes viable.

If the actual stability window `Scg` exceeds the hardcoded 37-hour cutoff:

1. An honest caught-up peer legitimately rolls back within the new `Scg` window (e.g., 50 hours old under a doubled `k`).
2. The syncing node fires `HistoricityException` and disconnects from that peer.
3. If all honest peers are similarly disconnected, the syncing node satisfies the HAA vacuously — it has no honest peers left.
4. An adversarial peer presenting a denser-looking but non-canonical chain (a long-range attack) now faces no Genesis density comparison against an honest reference chain.
5. The syncing node selects the adversarial chain, accepting an invalid ledger state.

This maps directly to the allowed High impact: **"genesis … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."**

---

### Likelihood Explanation

The trigger is a hard fork that increases `k` or decreases `f` (or introduces an era with a longer slot duration). Cardano has undergone multiple hard forks (Byron → Shelley → Allegra → Mary → Alonzo → Babbage → Conway → Dijkstra), and future protocol evolution is expected. The design document itself flags this as a known gap requiring a code update if `Scg` changes. The probability is non-zero and grows with each future era. The analogy to the original report is exact: just as EVM opcode repricing could silently break the 2300-gas assumption, a Cardano protocol parameter change silently breaks the 37-hour assumption — and in both cases the fix is to derive the value dynamically rather than hardcode it.

---

### Recommendation

Compute `HistoricityCutoff` from the actual runtime protocol parameters rather than hardcoding mainnet literals. Concretely, `mkGenesisConfig` should accept (or derive from the `TopLevelConfig`) the security parameter `k`, the active-slot coefficient `f`, and the maximum slot length across all supported eras, then compute:

```haskell
gcHistoricityCutoff = Just $ HistoricityCutoff $
    fromIntegral (3 * unNonZero (maxRollbacks k) * ceiling (1 / f))
    * maxSlotLengthSeconds
    + safetyMargin
```

This mirrors how `Sgen` is already implemented to vary dynamically across eras, closing the gap the design document explicitly identifies.

---

### Proof of Concept

**Setup:** A private testnet or future mainnet hard fork sets `k = 4320` (doubling the security parameter for stronger guarantees) while keeping `f = 0.05` and slot length = 1 s. The new stability window is `3 × 4320 × 20 = 259,200 s = 72 hours`.

**Attack sequence:**

1. A syncing node with Genesis enabled connects to a mix of honest and adversarial peers.
2. An honest caught-up peer, having experienced a legitimate rollback within the new 72-hour stability window, sends `MsgRollBackward` referencing a header whose slot time is 50 hours ago.
3. `mkCheck` evaluates `historicityCutoff (133,200 s) < actualRollbackAge (180,000 s)` → `True` → `HistoricityException` is thrown.
4. The ChainSync client disconnects from the honest peer.
5. With all honest peers disconnected, the adversarial peer presents a long-range alternative chain with higher apparent density in the GDD window.
6. The GDD has no honest reference chain to compare against; the LoE anchor advances along the adversarial chain.
7. The syncing node selects the adversarial chain, permanently committing to an invalid ledger state.

The entry point is entirely network-reachable: the adversarial peer is an unprivileged node that sends standard ChainSync protocol messages (`MsgRollForward` headers followed by a crafted `MsgRollBackward`). No key compromise, no operator action, and no stake majority is required on the adversary's part — the precondition (the hard fork) is a legitimate protocol evolution that the code fails to adapt to, exactly as `.transfer()`'s 2300-gas assumption fails to adapt to EVM repricing.

### Citations

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L76-86)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs (L148-151)
```haskell
    , -- Duration in seconds of one Cardano mainnet Shelley stability window
      -- (3k/f slots times one second per slot) plus one extra hour as a
      -- safety margin.
      gcHistoricityCutoff = Just $ HistoricityCutoff $ 3 * 2160 * 20 + 3600
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/HistoricityCheck.hs (L153-160)
```haskell
mkCheck systemTime getCurrentGsmState cshc =
  HistoricityCheck
    { judgeMessageHistoricity = \msg hswt ->
        getCurrentGsmState >>= \case
          PreSyncing -> judgeRollback msg hswt
          Syncing -> judgeRollback msg hswt
          CaughtUp -> pure $ Right ()
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node.hs (L573-577)
```haskell
                  historicityCheck getGsmState =
                    case gcHistoricityCutoff llrnGenesisConfig of
                      Nothing -> HistoricityCheck.noCheck
                      Just historicityCutoff ->
                        HistoricityCheck.mkCheck systemTime getGsmState historicityCutoff
```

**File:** docs/website/contents/references/miscellaneous/genesis_design.md (L634-637)
```markdown
- HistoricityCutoff = 36+1 hours.
  This value must be greater than Scg of the Cardano chain's current era, which is 36 hours, and will remain so for the foreseeable future.
  It seems very unlikely that the community will increase the upper bound on settlement time, but if they did, then HistoricityCutoff would need to increase accordingly.
  The extra hour is to eliminate corner cases/risks/etc --- eg 10 minutes would probably suffice just as well.
```

**File:** docs/website/contents/references/miscellaneous/genesis_design.md (L693-696)
```markdown
Other parameters such as MaxCaughtUpAge and HistoricityCutoff have this same caveat as Sgen.

One caveat: MaxCaughtUpAge and HistoricityCutoff are indeed constants in the implementation, but Sgen is actually implemented to vary as the chain transitions eras.
This is technically more complicated than necessary, superseding this specification, due to the planned use of Lightweight Checkpointing to prevent alternate Byron and Transitional Praos histories.
```
