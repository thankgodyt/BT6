### Title
Unauthenticated `DebugChainDepState` Query Exposes Live Praos/TPraos OCert Counters and Nonces via LocalStateQuery Miniprotocol - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs`)

---

### Summary

The `LocalStateQuery` miniprotocol server exposes a `DebugChainDepState` query that returns the full live `ChainDepState` for the Praos or TPraos protocol — including all operational certificate (OCert) counters keyed by pool cold-key hash, and all evolving/candidate/epoch nonces — to any process that can connect to the node's local socket. The NTC channel is documented as "trusted" but the consensus layer itself enforces no authentication or caller identity check before answering this query. Any unprivileged local process with socket access receives the complete `PraosState` (or `SL.ChainDepState` for TPraos) in serialised form.

---

### Finding Description

**Root cause — no authorization check in `localStateQueryServer`:**

`localStateQueryServer` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalStateQuery/Server.hs` dispatches every incoming query directly to `Query.answerQuery` with no caller identity check or query-class filter:

```haskell
handleQuery rk forker query = do
  result <- Query.answerQuery cfg forker query
  return $ SendMsgResult result (acquired rk forker)
``` [1](#0-0) 

`answerQuery` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Query.hs` dispatches `BlockQuery` variants to `answerPureBlockQuery` with no restriction:

```haskell
answerQuery config forker query = case query of
  BlockQuery (blockQuery :: BlockQuery blk footprint result) ->
    case sing :: Sing footprint of
      SQFNoTables ->
        answerPureBlockQuery config blockQuery
          <$> atomically (roforkerGetLedgerState forker)
``` [2](#0-1) 

**The sensitive query — `DebugChainDepState`:**

`DebugChainDepState` is defined as a production `BlockQuery` constructor with `const True` version support (available on every `ShelleyNodeToClientVersion`):

```haskell
DebugChainDepState ->
  headerStateChainDep hst
``` [3](#0-2) 

```haskell
DebugChainDepState -> const True
``` [4](#0-3) 

The returned type is `ChainDepState proto`, which for Praos is `PraosState`:

```haskell
data PraosState = PraosState
  { praosStateLastSlot        :: !(WithOrigin SlotNo)
  , praosStateOCertCounters   :: !(Map (KeyHash SL.BlockIssuer) Word64)
  , praosStateEvolvingNonce   :: !Nonce
  , praosStateCandidateNonce  :: !Nonce
  , praosStateEpochNonce      :: !Nonce
  , praosStatePreviousEpochNonce :: !Nonce
  , praosStateLabNonce        :: !Nonce
  , praosStateLastEpochBlockNonce :: !Nonce
  }
``` [5](#0-4) 

`praosStateOCertCounters` is the live map of `KeyHash BlockIssuer → Word64` — the exact counter values used by `doValidateKESSignature` to enforce the OCert counter monotonicity invariant (`m ≤ n ≤ m+1`):

```haskell
case currentIssueNo of
  Nothing -> throwError $ NoCounterForKeyHashOCERT hk
  Just m -> do
    m <= n ?! CounterTooSmallOCERT m n
    n <= m + 1 ?! CounterOverIncrementedOCERT m n
``` [6](#0-5) 

The same data is also available for TPraos via `SL.PrtclState` inside `TPraosState`: [7](#0-6) 

**Wire encoding — tag 13, no version gate:**

The query is encoded as `[1, 13]` on the wire and decoded unconditionally:

```haskell
(1, 13) -> return $ SomeBlockQuery DebugChainDepState
``` [8](#0-7) 

**Entry path:**

Any process that can open the node's local Unix socket connects via NTC, negotiates any `NodeToClientVersion ≥ V_16` (all current versions), and sends a `LocalStateQuery` `MsgAcquire VolatileTip` followed by `MsgQuery [0, [1, 13]]`. The `localStateQueryServer` handler answers immediately with the full serialised `PraosState`. [9](#0-8) 

---

### Impact Explanation

**Sensitive consensus state exposure (Medium — matches allowed scope).**

The `praosStateOCertCounters` map reveals the current OCert counter for every registered pool. An adversary who knows the current counter `m` for a target pool can craft a block header with counter `m+1` (the only valid next value) without needing to observe a real block from that pool. Combined with a separately obtained cold key (e.g., from a compromised or colluding pool operator), this removes the counter-guessing barrier that the OCert counter is designed to impose.

The nonce fields (`praosStateEvolvingNonce`, `praosStateCandidateNonce`, `praosStateEpochNonce`) expose the exact randomness inputs used by `validateVRFSignature`. An adversary with this data can pre-compute the VRF leader-election threshold for any slot and any pool whose VRF key is known, enabling precise prediction of the leader schedule — materially weakening the private leader schedule security property of Praos.

This matches the allowed impact: **"Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS."**

---

### Likelihood Explanation

The NTC socket is accessible to any process running as the same OS user as the node, or any process granted socket access (e.g., `cardano-cli`, `ogmios`, wallet backends). In many production deployments the socket is exposed to co-located services. No authentication credential is required beyond socket-level OS access. The query requires only a standard `cardano-cli` invocation or a minimal CBOR client. Likelihood is **Medium** — requires local socket access, which is a realistic attacker position for a co-located malicious process or a compromised wallet/tool.

---

### Recommendation

1. **Short term:** Gate `DebugChainDepState` (and `DebugNewEpochState`, `DebugEpochState`) behind a node-operator-controlled flag (e.g., `--enable-debug-queries`) that defaults to off. In `localStateQueryServer`, reject debug-class queries unless the flag is set, returning `AcquireFailure` or a new `QueryNotPermitted` error.

2. **Long term:** Introduce a query authorization layer in `localStateQueryServer` that classifies queries by sensitivity tier (public / operator-only / debug) and enforces the tier based on a configurable policy. Review whether `DebugChainDepState` needs to be a live production query at all, or whether it should be replaced by a purpose-built, minimal-disclosure query (e.g., exposing only the nonce needed for a specific API call, not the full `PraosState`).

---

### Proof of Concept

Connect to a running Cardano node's local socket and send the following CBOR sequence over the `LocalStateQuery` miniprotocol (after NTC version negotiation):

```
-- MsgAcquire VolatileTip
82 00 01

-- MsgQuery: BlockQuery (QueryIfCurrent (ShelleyBlock Conway) DebugChainDepState)
-- Top-level: [0, <BlockQuery>]
-- HFC: [0, <QueryIfCurrent>] -> era index for Conway (index 6 in Cardano HFC)
-- Shelley query tag 13: [1, 13]
82 00 <hfc-wrapped [1, 13]>
```

The node responds with `MsgResult` containing the CBOR-serialised `PraosState` (version-tagged list of 8 fields: last slot, OCert counter map, 6 nonces). Decode with the CDDL schema at `ouroboros-consensus-cardano/cddl/disk/ledger/praos.cddl`:

```
praosState = [withOrigin<slotno>,
              {* keyhash => word64},   -- OCert counters, one per registered pool
              nonce, nonce, nonce, nonce, nonce, nonce]
``` [10](#0-9) 

The second field of the decoded result is the live OCert counter map. The third through eighth fields are the six nonces. No authentication is required beyond OS-level socket access.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalStateQuery/Server.hs (L74-81)
```haskell
  handleQuery ::
    ResourceKey m ->
    ReadOnlyForker' m blk ->
    Query blk result ->
    m (ServerStQuerying blk (Point blk) (Query blk) m () result)
  handleQuery rk forker query = do
    result <- Query.answerQuery cfg forker query
    return $ SendMsgResult result (acquired rk forker)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Query.hs (L257-266)
```haskell
answerQuery config forker query = case query of
  BlockQuery (blockQuery :: BlockQuery blk footprint result) ->
    case sing :: Sing footprint of
      SQFNoTables ->
        answerPureBlockQuery config blockQuery
          <$> atomically (roforkerGetLedgerState forker)
      SQFLookupTables ->
        answerBlockQueryLookup config blockQuery forker
      SQFTraverseTables ->
        answerBlockQueryTraverse config blockQuery forker
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs (L437-438)
```haskell
      DebugChainDepState ->
        headerStateChainDep hst
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs (L563-563)
```haskell
    DebugChainDepState -> const True
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs (L990-990)
```haskell
    (1, 13) -> return $ SomeBlockQuery DebugChainDepState
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L268-286)
```haskell
data PraosState = PraosState
  { praosStateLastSlot :: !(WithOrigin SlotNo)
  , praosStateOCertCounters :: !(Map (KeyHash SL.BlockIssuer) Word64)
  -- ^ Operation Certificate counters
  , praosStateEvolvingNonce :: !Nonce
  -- ^ Evolving nonce
  , praosStateCandidateNonce :: !Nonce
  -- ^ Candidate nonce
  , praosStateEpochNonce :: !Nonce
  -- ^ Epoch nonce
  , praosStatePreviousEpochNonce :: !Nonce
  -- ^ Previous epoch nonce
  , praosStateLabNonce :: !Nonce
  -- ^ Nonce constructed from the hash of the previous block
  , praosStateLastEpochBlockNonce :: !Nonce
  -- ^ Nonce corresponding to the LAB nonce of the last block of the previous
  -- epoch
  }
  deriving (Generic, Show, Eq)
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L640-645)
```haskell
    case currentIssueNo of
      Nothing -> do
        throwError $ NoCounterForKeyHashOCERT hk
      Just m -> do
        m <= n ?! CounterTooSmallOCERT m n
        n <= m + 1 ?! CounterOverIncrementedOCERT m n
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/TPraos.hs (L542-552)
```haskell
  getOpCertCounters _prx cdst = opcertCounters
   where
    TPraosState{tpraosStateChainDepState} = cdst
    SL.ChainDepState
      { SL.csProtocol
      } = tpraosStateChainDepState
    SL.PrtclState
      opcertCounters
      _evolvingNonce
      _candidateNonce =
        csProtocol
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToClient.hs (L142-148)
```haskell
    , hStateQueryServer = \reg ->
        localStateQueryServer (ExtLedgerCfg cfg) $ \target ->
          ChainDB.allocInRegistryReadOnlyForkerAtPoint getChainDB target reg
    , hTxMonitorServer =
        localTxMonitorServer
          getMempool
    }
```

**File:** ouroboros-consensus-cardano/cddl/disk/ledger/praos.cddl (L1-12)
```text
versionedPraosState = [praosVersion, praosState]

praosVersion = 0

praosState = [withOrigin<slotno>,
              {* keyhash => word64},
              nonce,
              nonce,
              nonce,
              nonce,
              nonce,
              nonce]
```
