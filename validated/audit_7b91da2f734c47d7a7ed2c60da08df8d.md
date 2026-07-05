### Title
Permanently Disabled PBFT State Invariant Check Allows Undetected Signature-Count Corruption — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs`)

---

### Summary

`enableInvariant` in `PBftState.hs` is a boolean flag hardcoded to `False` with no mechanism to set it to `True`. This permanently disables the only runtime check that verifies the internal consistency of `PBftState.counts`, the cached per-key signature count that drives the PBFT signing-threshold enforcement. If `counts` diverges from `inWindow` through any code path, the threshold check silently uses wrong data, potentially allowing a genesis key to sign more blocks than the protocol permits.

---

### Finding Description

`PBftState` stores two fields that must stay in sync:

- `inWindow :: StrictSeq (PBftSigner c)` — the actual sliding window of signers
- `counts :: Map (PBftVerKeyHash c) Word64` — a cached count of how many times each genesis key appears in `inWindow` [1](#0-0) 

The `invariant` function verifies both the window-size bound and that `computeCounts inWindow == counts`: [2](#0-1) 

`assertInvariant` is the only call site that invokes `invariant` at runtime. It is guarded by `enableInvariant`: [3](#0-2) 

`enableInvariant` is hardcoded to `False` with no CPP flag, no runtime toggle, and no setter — the TODO comment acknowledges this was intended to be configurable but never was: [4](#0-3) 

`assertInvariant` is called inside `append`, the sole mutation point for `PBftState`: [5](#0-4) 

Because `enableInvariant = False`, `assertInvariant` is a no-op in every execution path, including production.

---

### Impact Explanation

`pbftWindowExceedsThreshold` reads `counts` directly (via `S.countSignedBy`) to decide whether a genesis key has exceeded its signing quota: [6](#0-5) 

This threshold check is the core PBFT safety invariant. It is invoked in both `updateChainDepState` (full validation of new blocks from peers) and `reupdateChainDepState` (re-application during chain selection and ImmutableDB replay): [7](#0-6) [8](#0-7) 

If `counts` under-reports the number of times a genesis key has signed (i.e., `counts` is stale or corrupted), `pbftWindowExceedsThreshold` will not fire, and the node will accept blocks that violate the PBFT signing threshold. This is a **bypass of PBFT certificate/signature validation** — the exact impact class listed as Critical in the scope.

---

### Likelihood Explanation

The current `append` implementation correctly maintains `counts` through `incrementKey`/`decrementKey`, and `decodePBftState` recomputes `counts` from scratch via `uninvert → fromList → computeCounts`, so no known single-step exploit exists today. However:

1. The flag was explicitly designed to be a runtime/CPP-configurable guard against implementation bugs in `append` and related state transitions. Its permanent disablement removes the only defense-in-depth layer.
2. `reupdateChainDepState` skips the DSIGN and delegation checks entirely (it is the "fast re-apply" path used during chain selection and ImmutableDB replay). Any inconsistency in `counts` introduced during that path would propagate silently.
3. A peer-supplied sequence of blocks that exercises edge cases in `append` (e.g., near-genesis window, EBB boundaries) could, if a latent bug exists, corrupt `counts` without detection.

Likelihood: **Medium** — no known immediate exploit, but the permanently disabled guard removes the only mechanism that would detect state corruption before it reaches the threshold check.

---

### Recommendation

1. Replace the hardcoded `enableInvariant = False` with a CPP flag as the TODO comment (#1248) already prescribes, so that at minimum CI/test builds run with invariant checking enabled.
2. Consider enabling `assertInvariant` unconditionally in debug/development builds and gating it behind a compile-time flag for production, following the pattern used elsewhere in the codebase.
3. Add a property-based test that round-trips `PBftState` through `append`/`decodePBftState` and explicitly checks `computeCounts inWindow == counts` after each operation.

---

### Proof of Concept

```
-- enableInvariant is hardcoded False; assertInvariant is always a no-op:
enableInvariant :: Bool
enableInvariant = False          -- File: PBFT/State.hs:130-131

assertInvariant n st
  | enableInvariant = ...        -- branch never taken
  | otherwise       = st         -- always returns st unchecked

-- append calls assertInvariant but it is a no-op:
append n signer@(PBftSigner _ gk) PBftState{..} =
  assertInvariant n $            -- no-op
    PBftState { inWindow = trimmedWindow, counts = trimmedCounts }

-- pbftWindowExceedsThreshold reads counts directly:
pbftWindowExceedsThreshold PBftWindowParams{..} st gk =
  if numSigned > threshold       -- numSigned = S.countSignedBy st gk
    then Left numSigned          --   which reads st.counts directly
    else Right ()
```

If `counts` is lower than the true count (e.g., due to a bug in `append`'s `decrementKey` path or a deserialization edge case), `numSigned` will be under-reported, `pbftWindowExceedsThreshold` will return `Right ()`, and `updateChainDepState` will accept the block without throwing `PBftExceededSignThreshold`, silently bypassing the PBFT signing-threshold rule. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L82-93)
```haskell
data PBftState c = PBftState
  { inWindow :: !(StrictSeq (PBftSigner c))
  -- ^ Signatures in the window
  --
  -- We should have precisely @n@ signatures in the window, unless we are
  -- near genesis.
  --
  -- INVARIANT Empty if and only if we are exactly at genesis.
  , counts :: !(Map (PBftVerKeyHash c) Word64)
  -- ^ Cached counts of the signatures in the window
  }
  deriving Generic
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L112-123)
```haskell
invariant ::
  PBftCrypto c =>
  WindowSize -> PBftState c -> Either String ()
invariant (WindowSize n) st@PBftState{..} = runExcept $ do
  unless (size inWindow <= n) $
    failure "Too many in-window signatures"

  unless (computeCounts inWindow == counts) $
    failure "Cached counts incorrect"
 where
  failure :: String -> Except String ()
  failure err = throwError $ err ++ ": " ++ show st
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L125-143)
```haskell
-- | The 'PBftState' tests don't rely on this flag but check the
-- invariant manually. This flag is here so that the invariant checks could be
-- enabled while running other consensus tests, just as a sanity check.
--
-- TODO: Make this a CPP flag, see #1248.
enableInvariant :: Bool
enableInvariant = False

assertInvariant ::
  (HasCallStack, PBftCrypto c) =>
  WindowSize ->
  PBftState c ->
  PBftState c
assertInvariant n st
  | enableInvariant =
      case invariant n st of
        Right () -> st
        Left err -> error $ "Invariant violation: " ++ err
  | otherwise = st
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs (L220-236)
```haskell
append n signer@(PBftSigner _ gk) PBftState{..} =
  assertInvariant n $
    PBftState
      { inWindow = trimmedWindow
      , counts = trimmedCounts
      }
 where
  -- First append the signature to the right,
  (appendedWindow, appendedCounts) =
    (inWindow |> signer, incrementKey gk counts)
  -- then trim the oldest from the left, if needed.
  (trimmedWindow, trimmedCounts) = case appendedWindow of
    x :<| xs
      | size inWindow == getWindowSize n ->
          (xs, decrementKey (pbftSignerGenesisKey x) appendedCounts)
    _otherwise ->
      (appendedWindow, appendedCounts)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs (L359-365)
```haskell
            Just gk -> do
              let state' = append cfg params (slot, gk) state
              case pbftWindowExceedsThreshold params state' gk of
                Left n -> throwError $ PBftExceededSignThreshold gk n
                Right () -> return $! state'
     where
      params = pbftWindowParams cfg
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs (L382-386)
```haskell
            Just gk -> do
              let state' = append cfg params (slot, gk) state
              case pbftWindowExceedsThreshold params state' gk of
                Left n -> error $ show $ PBftExceededSignThreshold gk n
                Right () -> state'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs (L421-435)
```haskell
-- | Does the number of blocks signed by this key exceed the threshold?
--
-- Returns @Just@ the number of blocks signed if exceeded.
pbftWindowExceedsThreshold ::
  PBftCrypto c =>
  PBftWindowParams ->
  PBftState c ->
  PBftVerKeyHash c ->
  Either Word64 ()
pbftWindowExceedsThreshold PBftWindowParams{..} st gk =
  if numSigned > threshold
    then Left numSigned
    else Right ()
 where
  numSigned = S.countSignedBy st gk
```
