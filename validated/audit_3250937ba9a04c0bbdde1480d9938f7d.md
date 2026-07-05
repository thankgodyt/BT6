### Title
Unenforced Duplicate-Peer Precondition in `cschcAddHandle` Desynchronizes Map/Sequence, Corrupting CSJ Dynamo Election - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/State.hs`)

---

### Summary

`newChainSyncClientHandleCollection` maintains two parallel views of connected peers — a `Map` and a `StrictSeq` — and documents a `PRECONDITION: The peer is not already in the collection` on `cschcAddHandle`. This precondition is never enforced. If `cschcAddHandle` is called twice for the same peer, `Map.insert` silently overwrites the map entry while `Seq.|>` unconditionally appends a second entry to the sequence. The two views diverge. Because `cschcRemoveHandle` only removes the **first** sequence occurrence, a subsequent disconnect leaves a ghost entry permanently in the sequence. All ChainSync Jumping (CSJ) dynamo/objector election functions operate exclusively on `cschcSeq`, so they can elect a disconnected ghost peer as the dynamo, causing the LoE anchor to stop advancing and blocking chain selection.

---

### Finding Description

In `newChainSyncClientHandleCollection`:

```haskell
cschcAddHandle = \peer handle -> do
    modifyTVar handlesMap (Map.insert peer handle)   -- silently overwrites
    modifyTVar handlesSeq (Seq.|> (peer, handle))    -- always appends
``` [1](#0-0) 

The comment on the field declaration states:

```
-- PRECONDITION: The peer is not already in the collection
``` [2](#0-1) 

No guard, assertion, or STM check enforces this. `cschcRemoveHandle` removes only the **first** sequence occurrence via `Seq.spanl`:

```haskell
cschcRemoveHandle = \peer -> do
    modifyTVar handlesMap (Map.delete peer)
    modifyTVar handlesSeq $ \s ->
        let (xs, ys) = Seq.spanl ((/= peer) . fst) s
         in xs Seq.>< Seq.drop 1 ys
``` [3](#0-2) 

**Corruption sequence:**
1. Peer P connects → `map = {P→h1}`, `seq = [(P,h1)]`
2. P reconnects (duplicate add) → `map = {P→h2}`, `seq = [(P,h1),(P,h2)]`
3. P disconnects → `map = {}`, `seq = [(P,h2)]` ← ghost entry remains

The ghost entry `(P,h2)` persists in the sequence with no live thread behind it.

`cschcAddHandle` is called from two production sites:

- `Client.hs:432` (CSJDisabled path): `cschcAddHandle varHandles peer handle` [4](#0-3) 

- `Jumping.hs:862` (CSJEnabled path): `cschcAddHandle (handlesCol context) peer handle` [5](#0-4) 

All CSJ election functions read exclusively from `cschcSeq`, not `cschcMap`:

- `getDynamo` scans `cschcSeq` to find the dynamo: [6](#0-5) 

- `backfillDynamo` reads `cschcSeq` to elect a replacement dynamo: [7](#0-6) 

- `promoteToDynamo` iterates `peerStates` (from `cschcSeq`) to demote all non-dynamo peers: [8](#0-7) 

- `electNewObjector` and `findObjector` also iterate `cschcSeq`: [9](#0-8) 

---

### Impact Explanation

The CSJ Dynamo is the sole peer from which a syncing node downloads all headers during Genesis sync. If a ghost entry is elected as dynamo via `findNonDisengaged` → `backfillDynamo`, no live thread is serving that peer's ChainSync session. The node will not receive new headers, the candidate fragment will not advance, and the LoE (Limit on Eagerness) anchor will not move. The GDD governor computes the LoE from candidate fragments; a frozen LoE means `ChainDB.triggerChainSelectionAsync` is never called with an updated LoE tip, permanently blocking chain selection advancement. This is a **High** chain-selection bug: an honest node is made to prefer no chain at all (stalled selection) over the canonical chain, violating sync liveness and the Genesis security assumption that an honest node will eventually adopt the best chain.

Additionally, `promoteToDynamo` writes to the ghost handle's `cschJumping` TVar (line 1019), mutating state that no live thread is observing, silently corrupting the CSJ role assignments for all remaining real peers.

---

### Likelihood Explanation

The Ouroboros connection manager permits a peer to reconnect after disconnection. During rapid reconnect/disconnect cycles (e.g., a flapping peer or a peer that disconnects mid-handshake and immediately reconnects), the `bracket_` cleanup of the old connection and the `cschcAddHandle` of the new connection can race within the same STM transaction window. Because `atomicallyWithMonotonicTime` wraps `cschcAddHandle` (Client.hs:429), and `cschcRemoveHandle` is in a separate `atomically` block (Client.hs:433), there is a real concurrent window where both the old and new connection threads are live and the new one inserts before the old one removes. Any unprivileged peer that can connect, disconnect, and reconnect rapidly — a normal network event — can trigger this condition without any special privileges.

---

### Recommendation

Enforce the precondition inside `cschcAddHandle` by checking for an existing entry before appending to the sequence:

```haskell
cschcAddHandle = \peer handle -> do
    existing <- Map.member peer <$> readTVar handlesMap
    when existing $ error "cschcAddHandle: peer already in collection"
    modifyTVar handlesMap (Map.insert peer handle)
    modifyTVar handlesSeq (Seq.|> (peer, handle))
```

For production robustness, replace the `error` with a structured exception or a silent idempotent upsert that also updates the sequence entry in-place (replacing the old handle rather than appending). Additionally, `cschcRemoveHandle` should remove **all** occurrences of the peer from the sequence (using `Seq.filter` instead of `Seq.spanl` + `Seq.drop 1`) to be safe against any future duplicate insertion.

---

### Proof of Concept

**Private testnet sequence:**

1. Start a node with Genesis/CSJ enabled (`CSJEnabled`).
2. Connect peer P — `registerClient` calls `cschcAddHandle`: `map={P→h1}`, `seq=[(P,h1)]`. P is elected dynamo.
3. Before P's `bracket_` cleanup fires (e.g., by racing a reconnect), connect P again — `cschcAddHandle` appends: `map={P→h2}`, `seq=[(P,h1),(P,h2)]`.
4. Disconnect P (first connection ends) — `cschcRemoveHandle` removes first occurrence: `map={}`, `seq=[(P,h2)]`.
5. Now `backfillDynamo` calls `findNonDisengaged` on `cschcSeq`, finds ghost `(P,h2)`, and calls `promoteToDynamo` with it as the new dynamo.
6. No live thread serves P's ChainSync session. The node's candidate fragment freezes. The LoE anchor does not advance. Chain selection is permanently blocked until the node is restarted. [10](#0-9) [7](#0-6) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/State.hs (L121-123)
```haskell
  , cschcAddHandle :: !(peer -> ChainSyncClientHandle m blk -> STM m ())
  -- ^ Add the handle for the given peer to the collection
  -- PRECONDITION: The peer is not already in the collection
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/State.hs (L159-166)
```haskell
      , cschcAddHandle = \peer handle -> do
          modifyTVar handlesMap (Map.insert peer handle)
          modifyTVar handlesSeq (Seq.|> (peer, handle))
      , cschcRemoveHandle = \peer -> do
          modifyTVar handlesMap (Map.delete peer)
          modifyTVar handlesSeq $ \s ->
            let (xs, ys) = Seq.spanl ((/= peer) . fst) s
             in xs Seq.>< Seq.drop 1 ys
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L429-434)
```haskell
          insertHandle = atomicallyWithMonotonicTime $ \time -> do
            gsmState <- getGsmState
            updateLopBucketConfig lopBucket gsmState time
            cschcAddHandle varHandles peer handle
          deleteHandle = atomically $ cschcRemoveHandle varHandles peer
      bracket_ insertHandle deleteHandle $ f Jumping.noJumping
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L753-755)
```haskell
getDynamo handlesCol = do
  handles <- cschcSeq handlesCol
  findM (\(_, handle) -> isDynamo <$> readTVar (cschJumping handle)) handles
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L854-863)
```haskell
registerClient gsmState context peer csState mkHandle = do
  (csjState, mbEv) <- case gsmState of
    GSM.CaughtUp -> pure (Disengaged DisengagedDone, Nothing)
    -- This branch disables CSJ while the GSM is in the CaughtUp state.
    GSM.PreSyncing -> engageClient context csState
    GSM.Syncing -> engageClient context csState
  cschJumping <- newTVar csjState
  let handle = mkHandle cschJumping
  cschcAddHandle (handlesCol context) peer handle
  pure (context{peer, handle}, mbEv)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L964-977)
```haskell
backfillDynamo context = do
  peerStates <- cschcSeq (handlesCol context)
  mDynamo <- do
    -- prefer a 'Started' 'Objector', if any exists
    findObjector context >>= \case
      Just (oId, Started, _oGoodJI, _oBad, oHandle) ->
        pure $ Just $ (oId, oHandle)
      _ ->
        findNonDisengaged peerStates
  case mDynamo of
    Nothing -> pure (NoLongerDynamo Nothing, Nothing)
    Just (dynId, dynamo) -> do
      promoteToDynamo peerStates dynId dynamo
      pure (NoLongerDynamo (Just dynId), Just (dynId, dynamo))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L1014-1020)
```haskell
  -- Demote all other peers to jumpers
  forM_ peerStates $ \(peer, st) ->
    when (peer /= dynId) $ do
      jumpingState <- readTVar (cschJumping st)
      when (not (isDisengaged jumpingState)) $
        newJumper mJumpInfo (Happy FreshJumper Nothing)
          >>= writeTVar (cschJumping st)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L1022-1028)
```haskell
-- | Find a non-disengaged peer in the given sequence
findNonDisengaged ::
  MonadSTM m =>
  StrictSeq (peer, ChainSyncClientHandle m blk) ->
  STM m (Maybe (peer, ChainSyncClientHandle m blk))
findNonDisengaged =
  findM $ \(_, st) -> not . isDisengaged <$> readTVar (cschJumping st)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs (L1041-1049)
```haskell
findObjector context =
  cschcSeq (handlesCol context) >>= go
 where
  go Seq.Empty = pure Nothing
  go ((peer, handle) Seq.:<| xs) =
    readTVar (cschJumping handle) >>= \case
      Objector initState goodJump badPoint ->
        pure $ Just (peer, initState, goodJump, badPoint, handle)
      _ -> go xs
```
