### Title
Unauthenticated `DebugChainDepState` Query Exposes Full Praos Consensus State Including Epoch Nonces and OCert Counters - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs`)

---

### Summary

The `DebugChainDepState` block query, served over the unauthenticated `LocalStateQuery` node-to-client mini-protocol, returns the complete `ChainDepState proto` — for Praos/TPraos this is the full `PraosState`/`TPraosState`, containing the live epoch nonce, candidate nonce, evolving nonce, and the authoritative operational-certificate counter map for every registered stake pool. The query carries no version restriction (`blockQueryIsSupportedOnVersion = const True`) and no access control. Any process that can reach the node's local socket can extract this state without authentication.

---

### Finding Description

`DebugChainDepState` is declared as a `BlockQuery` constructor in `Query.hs`:

```haskell
DebugChainDepState ::
  BlockQuery (ShelleyBlock proto era) QFNoTables (ChainDepState proto)
```

It is answered by directly returning the node's live header-state chain-dep state:

```haskell
DebugChainDepState ->
  headerStateChainDep hst
```

For `Praos c`, `ChainDepState (Praos c) = PraosState`, which carries:
- `praosStateEpochNonce :: Nonce` — the epoch nonce `η₀` fed into every VRF leader-election computation for the current epoch
- `praosStateCandidateNonce :: Nonce` — the nonce being accumulated for the next epoch
- `praosStateEvolvingNonce :: Nonce` — the in-progress evolving nonce
- `praosStateOCertCounters :: Map (KeyHash BlockIssuer) Word64` — the node's authoritative map of the last accepted OCert counter for every registered pool

The version-support predicate is unconditional:

```haskell
DebugChainDepState -> const True
```

The `LocalStateQuery` server dispatches every query without any authentication or authorization check:

```haskell
handleQuery rk forker query = do
  result <- Query.answerQuery cfg forker query
  return $ SendMsgResult result (acquired rk forker)
```

The server is wired into the node-to-client handler with no additional guard:

```haskell
hStateQueryServer = \reg ->
  localStateQueryServer (ExtLedgerCfg cfg) $ \target ->
    ChainDB.allocInRegistryReadOnlyForkerAtPoint getChainDB target reg
```

---

### Impact Explanation

**Medium — Public node API flaw that exposes sensitive consensus state.**

1. **Epoch nonce oracle.** `praosStateEpochNonce` is the seed `η₀` used in `mkInputVRF slot η₀` inside `checkIsLeader`. Any client that obtains `η₀` and knows a pool's public VRF verification key (all registered pools publish this on-chain) can compute the full leader schedule for the current epoch for that pool. This is the same computation the pool operator performs internally; the query makes it trivially available to any local client without requiring chain replay.

2. **Candidate nonce leakage.** `praosStateCandidateNonce` is the nonce being accumulated for the next epoch. Exposing it mid-epoch reveals the current trajectory of the next epoch's randomness, enabling early leader-schedule prediction for the upcoming epoch before the randomness stabilisation window closes.

3. **OCert counter oracle.** `praosStateOCertCounters` is the node's authoritative view of the last accepted OCert counter `m` for each pool. The OCERT rule accepts only `n ∈ {m, m+1}`. Knowing `m` precisely narrows the valid counter range to two values, which is directly useful when constructing a forged block header (the attacker still needs the cold key to sign the OCert and the KES key to sign the header, but the counter constraint is resolved without chain scanning).

4. **No access control.** The `LocalStateQuery` protocol is node-to-client; in practice any wallet, CLI tool, monitoring agent, or co-located process with socket access can issue this query. There is no authentication, no capability check, and no version gate.

---

### Likelihood Explanation

**Medium.** The node-to-client socket is typically restricted to localhost, but in cloud deployments, containerised environments, or shared infrastructure, multiple unprivileged processes routinely have socket access. The query requires only a standard `LocalStateQuery` client (e.g., `cardano-cli query`). No special privileges, no chain replay, and no cryptographic material are needed to issue it. The `const True` version predicate means it is reachable on every deployed node version.

---

### Recommendation

1. **Restrict `DebugChainDepState` by version.** Assign it a dedicated `ShelleyNodeToClientVersion` and set `blockQueryIsSupportedOnVersion` to `(>= vDebugChainDepState)`, then gate that version behind an explicit opt-in flag (analogous to how `DebugLedgerConfig` was gated behind `QueryVersion3`).

2. **Consider removing or deprecating the query.** The comment already states "Only for debugging purposes, we make no effort to ensure binary compatibility." If no production consumer requires it, it should be removed from the supported query set or restricted to a debug-only build flag.

3. **Audit all `const True` entries in `blockQueryIsSupportedOnVersion`.** `DebugEpochState`, `DebugNewEpochState`, and `DebugChainDepState` all return `const True`. Each should be reviewed for whether unrestricted availability is intentional.

---

### Proof of Concept

```
# On a node with a reachable local socket:
cardano-cli query protocol-state \
  --socket-path /path/to/node.socket \
  --mainnet
```

This issues `DebugChainDepState` (tag `[1, 13]` in the Shelley query codec) and returns the serialised `PraosState`, including `praosStateEpochNonce` and `praosStateOCertCounters`, to any unauthenticated caller. No credentials, no chain replay, no operator involvement required.

---

**Root-cause chain:** [1](#0-0) 

`DebugChainDepState` returns `headerStateChainDep hst` — the live `PraosState`: [2](#0-1) 

No version restriction: [3](#0-2) 

`LocalStateQuery` server dispatches without authentication: [4](#0-3) 

Wired into the node-to-client handler with no guard: [5](#0-4) 

`PraosState` fields that are exposed (epoch nonce, OCert counters): [6](#0-5) 

Epoch nonce used directly in leader election: [7](#0-6)

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query.hs (L211-214)
```haskell
  -- | Only for debugging purposes, we make no effort to ensure binary
  -- compatibility (cf the comment on 'GetCBOR').
  DebugChainDepState ::
    BlockQuery (ShelleyBlock proto era) QFNoTables (ChainDepState proto)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalStateQuery/Server.hs (L79-81)
```haskell
  handleQuery rk forker query = do
    result <- Query.answerQuery cfg forker query
    return $ SendMsgResult result (acquired rk forker)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToClient.hs (L142-144)
```haskell
    , hStateQueryServer = \reg ->
        localStateQueryServer (ExtLedgerCfg cfg) $ \target ->
          ChainDB.allocInRegistryReadOnlyForkerAtPoint getChainDB target reg
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L389-396)
```haskell
instance PraosCrypto c => ConsensusProtocol (Praos c) where
  type ChainDepState (Praos c) = PraosState
  type IsLeader (Praos c) = PraosIsLeader c
  type CanBeLeader (Praos c) = PraosCanBeLeader c
  type TiebreakerView (Praos c) = PraosTiebreakerView c
  type LedgerView (Praos c) = Views.LedgerView
  type ValidationErr (Praos c) = PraosValidationErr c
  type ValidateView (Praos c) = PraosValidateView c
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L416-422)
```haskell
      chainState = tickedPraosStateChainDepState cs
      lv = tickedPraosStateLedgerView cs
      eta0 = praosStateEpochNonce chainState
      vkhCold = SL.hashKey praosCanBeLeaderColdVerKey
      rho' = mkInputVRF slot eta0

      rho = VRF.evalCertified () rho' praosCanBeLeaderSignKeyVRF
```
