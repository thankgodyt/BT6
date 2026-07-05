### Title
Peras Certificate Boost Frozen at Validation Time Causes Permanent Chain Selection Imbalance When `perasWeight` Changes - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The Peras protocol stores the chain-selection weight boost (`vpcCertBoost`) inside each `ValidatedPerasCert` at the moment of certificate validation, reading it directly from the current `PerasParams.perasWeight`. The `PerasCertDB` persists these frozen boost values, and `implGetWeightSnapshot` reconstructs the `PerasWeightSnapshot` used in chain selection by reading those frozen values. When `perasWeight` changes (a normal governance operation explicitly anticipated in the design), all previously stored certificates retain their old boost, while newly arriving certificates receive the new boost. This creates a permanent, irrecoverable chain selection imbalance analogous to the FrankenDAO staking bonus freeze.

---

### Finding Description

**Step 1 — Boost is frozen at validation time.**

`validatePerasCert` (the degenerate instance used in production) stores `perasWeight params` directly into `vpcCertBoost`:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert
    { vpcCert = cert
    , vpcCertBoost = perasWeight params   -- frozen here
    }
``` [1](#0-0) 

Both inbound certificate pool writers call `validatePerasCert mkPerasParams` — the hardcoded static params — so every certificate that arrives is stamped with the `perasWeight` value that was current at validation time: [2](#0-1) [3](#0-2) 

**Step 2 — Frozen boost is persisted in `PerasCertDB`.**

`implAddCert` stores the entire `ValidatedPerasCert` (including its frozen `vpcCertBoost`) in `pcdsCertsByTicket`: [4](#0-3) 

**Step 3 — Chain selection reads the frozen boost.**

`implGetWeightSnapshot` reconstructs the `PerasWeightSnapshot` by calling `getPerasCertBoost cert` on every stored certificate — reading the frozen value, not the current `perasWeight`:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
``` [5](#0-4) 

This snapshot is then consumed by `chainSelection` via `preferAnchoredCandidate` / `weightedSelectView` to decide which chain to prefer: [6](#0-5) 

**Step 4 — `perasWeight` is explicitly designed to change.**

The `mkPerasParams` comment states: *"in the future this will depend on a concrete `BlockConfig`"*, and the field `perasWeight = PerasWeight 15` is a placeholder pending final governance decisions: [7](#0-6) 

There is no mechanism to re-validate or re-stamp stored certificates when `perasWeight` changes.

---

### Impact Explanation

**High — Chain selection bug.**

When `perasWeight` is increased via a governance/parameter update:
- Blocks boosted by certificates stored before the change retain the old (lower) boost.
- Blocks boosted by certificates arriving after the change receive the new (higher) boost.
- An adversary who pre-positions certificates on a fork before the parameter change can ensure that fork retains a permanently lower weight, making honest nodes less likely to switch to it — or conversely, if the adversary controls the timing of the parameter change, they can ensure their fork has the higher boost.

When `perasWeight` is decreased:
- Blocks boosted before the change retain the old (higher) boost permanently.
- An adversary who boosted a fork before the decrease retains a permanent chain-weight advantage over any competing chain boosted after the decrease.

In both cases, the `PerasWeightSnapshot` used in `chainSelection` is permanently inconsistent, and honest nodes may irreversibly prefer a non-canonical chain. There is no "poke" or re-normalization mechanism.

---

### Likelihood Explanation

**Medium.** The `perasWeight` parameter is explicitly designed to be configurable (the comment in `mkPerasParams` says it will depend on `BlockConfig`). A governance vote to adjust `perasWeight` is a normal, anticipated protocol operation. Any such change immediately triggers the imbalance for all certificates already in the `PerasCertDB`. An unprivileged peer can trigger the vulnerable path simply by sending a valid Peras certificate before a parameter change, which is the normal operation of the Peras mini-protocol.

---

### Recommendation

The `PerasWeightSnapshot` should be computed dynamically using the **current** `perasWeight` parameter rather than the frozen `vpcCertBoost` stored at validation time. Concretely:

1. Remove `vpcCertBoost` from `ValidatedPerasCert`, or treat it as a hint only.
2. In `implGetWeightSnapshot`, accept the current `PerasParams` as an argument and compute `perasWeight params` on the fly for each certificate, rather than reading `getPerasCertBoost cert`.
3. Alternatively, implement a re-normalization sweep (analogous to the "poke" function recommended in the external report) that re-stamps all stored certificates whenever `perasWeight` changes.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node. `perasWeight = PerasWeight 15` (from `mkPerasParams`).
2. A peer sends a valid Peras certificate for block B on fork F. The certificate is validated: `vpcCertBoost = PerasWeight 15`. It is stored in `PerasCertDB`.
3. A governance vote changes `perasWeight` to `PerasWeight 5`.
4. A peer sends a new Peras certificate for block B' on the canonical chain. It is validated: `vpcCertBoost = PerasWeight 5`.
5. `implGetWeightSnapshot` returns: fork F has boost 15, canonical chain has boost 5.
6. `chainSelection` calls `preferAnchoredCandidate` using this snapshot. Fork F appears heavier than the canonical chain by 10 weight units per boosted block.
7. The honest node switches to fork F — a non-canonical chain — due to the stale boost imbalance.

The entry path is entirely unprivileged: steps 2 and 4 require only sending valid Peras certificates over the Peras certificate mini-protocol, which any peer can do. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-127)
```haskell
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L181-183)
```haskell
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1128-1132)
```haskell
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L134-172)
```haskell
-- | Instantiate default Peras protocol parameters.
--
-- NOTE: in the future this will depend on a concrete 'BlockConfig'.
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
