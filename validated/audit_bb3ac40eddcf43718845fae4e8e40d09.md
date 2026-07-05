### Title
Truncating Integer Division in `mkUpperBound` Computes Incorrect Peras Era-Boundary Round Numbers, and `invariantSummary` Is Never Called on Deserialized `Summary` Objects — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs`)

---

### Summary

`mkUpperBound` computes the Peras round number at an era boundary using integer floor-division (`div`) without enforcing the required divisibility invariant at construction time. The companion check `invariantSummary` is never invoked on a `Summary` that arrives over the wire via the `LocalStateQuery` mini-protocol. A malicious node can therefore serve a crafted `Summary` whose `boundPerasRound` fields are arbitrarily wrong. Any client that uses this `Summary` to resolve slot↔Peras-round mappings will compute incorrect round numbers, accept or reject certificates for the wrong rounds, and apply Peras weight boosts to the wrong blocks — breaking chain selection.

---

### Finding Description

**Root cause — wrong rounding in `mkUpperBound`**

`mkUpperBound` is the single function that constructs every era-boundary `Bound`, including its `boundPerasRound` field:

```haskell
-- Summary.hs lines 133-138
inEraEpochs, inEraSlots :: Word64
inEraEpochs = countEpochs hiEpoch (boundEpoch lo)
inEraSlots  = inEraEpochs * unEpochSize eraEpochSize

inEraPerasRounds :: PerasEnabled Word64
inEraPerasRounds =
  div <$> PerasEnabled inEraSlots
      <*> (unPerasRoundLength <$> eraPerasRoundLength)
```

`div` is Haskell's floor-division. If `inEraSlots` is not an exact multiple of `perasRoundLength`, the result is silently truncated. The `EraSummary` comment documents the required invariant:

```
-- > epochSize % perasRoundLength == 0
-- i.e. the round length should divide the epoch size
```

This invariant is checked only inside `invariantSummary` (lines 500–513), and only for bounded eras. It is **never enforced at construction time** and **never called on a deserialized `Summary`**.

**Missing validation on the deserialization path**

The `Serialise` instance for `Bound` decodes `boundPerasRound` as a raw `Word64` with no cross-field validation:

```haskell
-- Summary.hs lines 540-549
decode = do
  len <- decodeListLen
  boundTime  <- decode
  boundSlot  <- decode
  boundEpoch <- decode
  boundPerasRound <- case len of
    3 -> pure NoPerasEnabled
    4 -> PerasEnabled <$> decode          -- arbitrary Word64, no check
    _ -> cborError ...
  return Bound{..}
```

`EraSummary` and `Summary` are decoded the same way — no call to `invariantSummary` anywhere in the production code path. The exported `invariantSummary` function appears only in test infrastructure.

**How the incorrect boundary propagates**

Every Peras round query goes through `evalExprInEra` in `Qry.hs`. The guard for `ERelToAbsPerasRoundNo` is:

```haskell
-- Qry.hs lines 340-342
guardEndPeras $ \end -> do
  eraEndPerasRound <- PerasEnabledT . Just $ boundPerasRound end
  pure $ absPerasRound <= eraEndPerasRound
```

If `boundPerasRound end` is wrong (too low or too high), rounds that belong to the next era are accepted in the current era, or rounds that belong to the current era are rejected. Every downstream consumer — `slotToPerasRoundNo`, `perasRoundNoToSlot`, certificate arrival-threshold checks, and Peras weight-boost computation in `weightedSelectView` — inherits the error.

---

### Impact Explanation

A client that receives a crafted `Summary` via `LocalStateQuery` and uses it to validate Peras certificates will:

1. Map slots near era boundaries to wrong Peras round numbers.
2. Accept certificates whose `pcCertRound` falls in the wrong era (or reject valid ones).
3. Apply `vpcCertBoost` weight to the wrong blocks in `wsvTotalWeight` / `preferCandidate`.
4. Prefer a non-canonical, adversarially-boosted chain over the honest chain.

This matches the "High" impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The attack requires:
- Peras to be activated (the code is present and the `eraPerasRoundLength` field is wired into `EraParams`; activation is a governance decision, not a code change).
- A client (wallet, light client, or any consumer of `LocalStateQuery`) to connect to a malicious node — a realistic scenario given that clients routinely connect to public nodes.

No privileged keys, stake majority, or operator compromise is required. The attacker only needs to run a node that serves a crafted CBOR-encoded `Summary`.

---

### Recommendation

1. **Enforce the invariant at deserialization time.** Call `invariantSummary` (or an equivalent check) inside the `Serialise` `decode` instance for `Summary`, and reject any `Summary` that fails.

2. **Enforce the invariant at construction time.** Add a `HasCallStack =>` assertion inside `mkUpperBound` that `inEraSlots `mod` perasRoundLength == 0` before performing the division, so that a misconfigured `EraParams` is caught immediately rather than silently truncated.

3. **Validate `boundPerasRound` against `boundSlot` and `eraPerasRoundLength`.** After decoding a `Bound`, verify that `boundPerasRound == boundSlot / perasRoundLength` (modulo era-start offset) to detect any wire-level tampering.

---

### Proof of Concept

**Step 1 — Attacker constructs a malicious `Summary`.**

Suppose the honest era has `epochSize = 432000`, `perasRoundLength = 90`, so the correct `boundPerasRound` at the era end (say epoch 500, slot 216_000_000) is `216_000_000 / 90 = 2_400_000`. The attacker encodes a `Bound` with `boundPerasRound = 1_200_000` (half the correct value).

**Step 2 — Attacker serves the crafted `Summary` via `LocalStateQuery`.**

The `Serialise` `decode` for `Summary` accepts the object without calling `invariantSummary`.

**Step 3 — Client queries `slotToPerasRoundNo` for a slot near the era boundary.**

`evalExprInEra` evaluates `EAbsToRelPerasRoundNo`, computes `roundInEra`, then `ERelToAbsPerasRoundNo` adds `eraStartPerasRound`. The guard `absPerasRound <= eraEndPerasRound` uses the attacker-supplied `1_200_000` as the ceiling, so rounds `1_200_001 … 2_400_000` — the entire second half of the era — are reported as `PastHorizonException` (out of range) even though they are valid.

**Step 4 — Client rejects valid certificates.**

`votesReachQuorum` / `stakeAboveThreshold` is called for a certificate whose `pcCertRound` falls in the suppressed range. The client cannot resolve the round to a slot, treats the certificate as invalid, and does not apply the `vpcCertBoost` weight. The adversary's chain (which carries a fake certificate for a round the client *can* resolve) receives the boost instead, and `preferCandidate` selects it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L133-141)
```haskell
  inEraEpochs, inEraSlots :: Word64
  inEraEpochs = countEpochs hiEpoch (boundEpoch lo)
  inEraSlots = inEraEpochs * unEpochSize eraEpochSize

  inEraPerasRounds :: PerasEnabled Word64
  inEraPerasRounds = div <$> PerasEnabled inEraSlots <*> (unPerasRoundLength <$> eraPerasRoundLength)

  inEraTime :: NominalDiffTime
  inEraTime = fromIntegral inEraSlots * getSlotLength eraSlotLength
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L195-197)
```haskell
-- Ouroboros Peras adds an invariant relating epoch size and Peras voting round lengths:
-- > epochSize % perasRoundLength == 0
-- i.e. the round length should divide the epoch size
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L500-513)
```haskell
        case eraPerasRoundLength curParams of
          NoPerasEnabled -> pure ()
          PerasEnabled perasRoundLength ->
            unless
              ( (unEpochSize $ eraEpochSize curParams)
                  `mod` (unPerasRoundLength perasRoundLength)
                  == 0
              )
              $ throwError
              $ mconcat
                [ "Invalid Peras round length "
                , show curSummary
                , " (Peras round length does not divide epoch size)"
                ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs (L540-549)
```haskell
  decode = do
    len <- decodeListLen
    boundTime <- decode
    boundSlot <- decode
    boundEpoch <- decode
    boundPerasRound <- case len of
      3 -> pure NoPerasEnabled
      4 -> PerasEnabled <$> decode
      _ -> cborError (DecoderErrorCustom "Bound" "unexpected list length")
    return Bound{..}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L335-343)
```haskell
  go (ERelToAbsPerasRoundNo expr) = runPerasEnabledT $ do
    eraStartPerasRound <- PerasEnabledT . Just $ boundPerasRound eraStart
    relPerasRound <- PerasEnabledT $ go expr
    let absPerasRound = addPerasRounds (getPerasRoundNoInEra relPerasRound) eraStartPerasRound

    guardEndPeras $ \end -> do
      eraEndPerasRound <- PerasEnabledT . Just $ boundPerasRound end
      pure $ absPerasRound <= eraEndPerasRound
    pure absPerasRound
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L365-368)
```haskell
  go (ERelSlotToPerasRoundNo expr) = runPerasEnabledT $ do
    SlotInEra relSlot <- lift $ go expr
    PerasRoundLength perasRoundLength <- PerasEnabledT . Just $ eraPerasRoundLength
    pure . bimap PerasRoundNoInEra SlotInPerasRound $ relSlot `divMod` perasRoundLength
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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
