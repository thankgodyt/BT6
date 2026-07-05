### Title
LoP Bucket Instantly Refilled to Full Capacity on Every GSM State Transition Allows Adversarial Peers to Indefinitely Withhold Headers - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs)

### Summary

The `updateLopBucketConfig` function in `Client.hs` unconditionally resets the Limit-on-Patience (LoP) leaky bucket to **full capacity** on every GSM state transition, discarding all prior drain history for every connected peer. This is the direct analog of `RateLimit.configureCaller`: just as that function sets the allowance map to `amount` regardless of prior usage, `updateLopBucketConfig` sets the bucket level to `LeakyBucket.capacity config` regardless of how much the peer had already drained. An adversarial peer that exploits natural `PreSyncing → Syncing` transitions can have its LoP budget reset to the full 100,000-token default (≈ 200 s of header-withholding tolerance) an unbounded number of times, defeating the LoP's purpose of forcing peers to reveal chain sparseness within a bounded window and thereby stalling the Genesis Density Disconnector (GDD).

### Finding Description

`bracketChainSyncClient` in `Client.hs` starts the bucket with a `dummyConfig` (capacity = 0, rate = 0) and immediately calls `updateLopBucketConfig` to set the real configuration based on the current GSM state:

```haskell
-- Client.hs L473-477
updateLopBucketConfig :: LeakyBucket.Handlers m -> GsmState -> Time -> STM m ()
updateLopBucketConfig lopBucket gsmState =
  LeakyBucket.updateConfig lopBucket $ \_ ->          -- ← old level DISCARDED
    let config = lopBucketConfig gsmState
     in (LeakyBucket.capacity config, config)          -- ← always full capacity
```

The lambda `\_ ->` ignores the `(oldLevel, oldConfig)` pair passed by `updateConfig` and unconditionally returns `(LeakyBucket.capacity config, config)`. The comment on the same lines acknowledges this:

> `-- NOTE: The new level is currently the maximal capacity of the bucket; maybe we want to change that later.`

`updateConfig` in `LeakyBucket.hs` then clamps the returned level to `[0, newCapacity]`:

```haskell
-- LeakyBucket.hs L272-274
let (newLevel, newConfig) = f (oldLevel, oldConfig)
    Config{capacity = newCapacity} = newConfig
    newLevel' = clamp (0, newCapacity) newLevel
```

Because `newLevel = capacity`, the clamp is a no-op and the bucket is written back at full capacity.

This callback is registered as `cschOnGsmStateChanged` on every `ChainSyncClientHandle` and is invoked for **all** connected peers atomically whenever the GSM writes a new state:

```haskell
-- NodeKernel.hs L327-331
, GSM.writeGsmState = \gsmState ->
    atomicallyWithMonotonicTime $ \time -> do
      writeTVar varGsmState gsmState
      handles <- cschcMap varChainSyncHandles
      traverse_ (($ time) . ($ gsmState) . cschOnGsmStateChanged) handles
```

The GSM transitions `PreSyncing → Syncing` whenever the Honest Availability Assumption (HAA) becomes satisfied. Each such transition resets every peer's LoP bucket to full capacity, regardless of how many tokens that peer had already consumed.

### Impact Explanation

The LoP is a foundational component of Ouroboros Genesis. Its purpose is to force adversarial peers to reveal their chain's sparseness within a bounded time window (`capacity / rate` = 200 s at defaults), so the GDD can evaluate density and disconnect them. If the budget is reset to full on every `PreSyncing → Syncing` transition, an adversarial peer can withhold headers indefinitely across transitions, preventing the GDD from ever accumulating enough density evidence to disconnect it. With the GDD stalled, the LoE anchor cannot advance, and the syncing node cannot make chain-selection progress. In the worst case—where the adversarial peer is the CSJ Dynamo—it retains disproportionate influence over the syncing node's chain selection for an unbounded duration, creating a realistic path to the node preferring a non-canonical, less-secure chain beyond the intended Genesis security assumptions.

### Likelihood Explanation

The adversarial peer cannot directly trigger GSM transitions, but the `PreSyncing → Syncing` transition fires whenever the HAA is satisfied, which occurs naturally during syncing as honest peers connect. A coordinated adversary controlling a fraction of outbound peer slots can cause the HAA to oscillate (by connecting and disconnecting peers) to repeatedly reset the LoP budget for a target adversarial peer that is simultaneously withholding headers. No privileged access, key material, or stake majority is required—only the ability to establish multiple outbound connections to the victim node, which is the normal operating model for any network peer.

### Recommendation

Preserve the old bucket level when reconfiguring. Replace the discarding lambda with one that carries the drained level forward, clamped to the new capacity:

```haskell
updateLopBucketConfig lopBucket gsmState =
  LeakyBucket.updateConfig lopBucket $ \(oldLevel, _oldConfig) ->
    let config = lopBucketConfig gsmState
     in (oldLevel, config)   -- level preserved; clamp in updateConfig handles overflow
```

This mirrors the recommendation in the external report: initialize the allowance to 0 (or, here, preserve the already-drained level) rather than granting the full new capacity instantly.

### Proof of Concept

1. Victim node enters `Syncing`; adversarial peer `A` connects. `updateLopBucketConfig` fires → bucket set to 100,000 tokens.
2. `A` withholds headers; bucket drains at 500 tokens/s. After 190 s, ~5,000 tokens remain (10 s until disconnection).
3. A second adversarial peer `B` (controlled by the same attacker) disconnects, causing the HAA to drop below threshold.
4. GSM writes `PreSyncing` → `updateLopBucketConfig` fires for all peers → `A`'s bucket is reset to `dummyConfig` (LoP disabled).
5. `B` reconnects; HAA is satisfied again. GSM writes `Syncing` → `updateLopBucketConfig` fires → `A`'s bucket is reset to **100,000 tokens**.
6. `A` continues withholding headers. Repeat from step 3.

`A` never exhausts its LoP budget. The GDD never receives the density evidence it needs to disconnect `A`. The LoE anchor does not advance. The syncing node's chain selection remains under `A`'s influence indefinitely. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L470-477)
```haskell
    -- \| Update the configuration of the bucket to match the given GSM state.
    -- NOTE: The new level is currently the maximal capacity of the bucket;
    -- maybe we want to change that later.
    updateLopBucketConfig :: LeakyBucket.Handlers m -> GsmState -> Time -> STM m ()
    updateLopBucketConfig lopBucket gsmState =
      LeakyBucket.updateConfig lopBucket $ \_ ->
        let config = lopBucketConfig gsmState
         in (LeakyBucket.capacity config, config)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/LeakyBucket.hs (L258-285)
```haskell
  updateConfig ::
    StrictTMVar m Int ->
    Bucket m ->
    ((Rational, Config m) -> (Rational, Config m)) ->
    Time ->
    STM m ()
  updateConfig leakingPeriodVersionTMVar bucket f time = do
    State
      { level = oldLevel
      , paused
      , configGeneration = oldConfigGeneration
      , config = oldConfig
      } <-
      snapshot bucket time
    let (newLevel, newConfig) = f (oldLevel, oldConfig)
        Config{capacity = newCapacity} = newConfig
        newLevel' = clamp (0, newCapacity) newLevel
    writeTVar bucket $
      State
        { level = newLevel'
        , time
        , paused
        , configGeneration = oldConfigGeneration + 1
        , config = newConfig
        }
    -- Ensure that 'leakingPeriodVersionTMVar' is empty, then maybe start the thread.
    mLeakingPeriodVersion <- tryTakeTMVar leakingPeriodVersionTMVar
    maybeStartThread mLeakingPeriodVersion leakingPeriodVersionTMVar bucket time
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/LeakyBucket.hs (L287-302)
```haskell
-- | Initialise a bucket given a configuration. The bucket starts full at the
-- time where one calls 'init'.
init ::
  (MonadMonotonicTime m, MonadSTM m, NoThunks (m ())) =>
  Config m ->
  m (Bucket m)
init config@Config{capacity} = do
  time <- getMonotonicTime
  newTVarIO $
    State
      { time
      , level = capacity
      , paused = False
      , configGeneration = 0
      , config = config
      }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs (L327-331)
```haskell
                , GSM.writeGsmState = \gsmState ->
                    atomicallyWithMonotonicTime $ \time -> do
                      writeTVar varGsmState gsmState
                      handles <- cschcMap varChainSyncHandles
                      traverse_ (($ time) . ($ gsmState) . cschOnGsmStateChanged) handles
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/State.hs (L91-93)
```haskell
  , cschOnGsmStateChanged :: !(GsmState -> Time -> STM m ())
  -- ^ Callback called by the GSM when the GSM state changes. They take the
  -- current time and should execute rapidly. Used to enable/disable the LoP.
```
