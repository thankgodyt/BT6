### Title
Pause Flag-Replacement in `_pause` Allows `deployToken` to Be Inadvertently Unpaused After `pauseAll()` — (`evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

---

### Summary

`_pause(flags)` is a **setter** (full replacement), not an **adder** (bitwise OR). After `pauseAll()` sets all three flags, a subsequent `pause(PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER)` call **replaces** the stored value with `0b011`, silently clearing `PAUSED_DEPLOY_TOKEN` (bit 2). `deployToken` then passes its `whenNotPaused(PAUSED_DEPLOY_TOKEN)` guard and can be called by anyone holding a valid pre-issued signature.

---

### Finding Description

**Root cause — `_pause` is a replacement, not an accumulator:** [1](#0-0) 

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // ← full replacement
    emit Paused(_msgSender(), $._pausedFlags);
}
```

**`pauseAll()` sets all three bits (value = 7):** [2](#0-1) 

**`pause(flags)` passes the caller-supplied bitmask directly to `_pause`:** [3](#0-2) 

**Flag constants:** [4](#0-3) 

```
PAUSED_INIT_TRANSFER  = 1 << 0  (bit 0)
PAUSED_FIN_TRANSFER   = 1 << 1  (bit 1)
PAUSED_DEPLOY_TOKEN   = 1 << 2  (bit 2)
```

**Exploit sequence:**

| Step | Call | `_pausedFlags` after |
|------|------|----------------------|
| 1 | `pauseAll()` | `0b111` = 7 (all paused) |
| 2 | `pause(PAUSED_FIN_TRANSFER \| PAUSED_INIT_TRANSFER)` = `pause(3)` | `0b011` = 3 — **bit 2 cleared** |
| 3 | `paused(PAUSED_DEPLOY_TOKEN)` = `(3 & 4) != 0` | **`false`** |

Step 2 is a natural admin action: "keep finTransfer and initTransfer paused." The admin has no reason to suspect it silently unpauses `deployToken`.

**`deployToken` guard now passes:** [5](#0-4) 

```solidity
function deployToken(
    bytes calldata signatureData,
    BridgeTypes.MetadataPayload calldata metadata
) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

The only remaining check is a valid `nearBridgeDerivedAddress` ECDSA signature over the metadata. Signatures for pending token deployments are issued by the bridge's MPC key before the emergency; an attacker who received such a signature (or a relayer replaying a queued deployment) can call `deployToken` successfully.

**Token is registered:** [6](#0-5) 

```solidity
isBridgeToken[address(bridgeTokenProxy)] = true;
ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
nearToEthToken[metadata.token] = address(bridgeTokenProxy);
```

---

### Impact Explanation

A new `BridgeToken` ERC1967 proxy is deployed and permanently bound to a NEAR token ID during an active emergency pause. Once `finTransfer` is later unpaused, `finTransfer` will mint tokens to any recipient for that token address because `isBridgeToken[proxy] == true`: [7](#0-6) 

If the emergency was triggered by a signing-key incident, a pre-issued signature can be replayed to bind a malicious or duplicate token, enabling unauthorized minting once the pause is lifted. This is a **pause bypass** and **unauthorized token binding** within the Critical scope.

---

### Likelihood Explanation

- The admin action `pause(PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER)` is the intuitive way to express "keep only these two operations paused." Nothing in the interface signals that it also unpauses `deployToken`.
- Pre-issued metadata signatures are a normal part of the bridge's token-onboarding flow; a queued deployment payload is a realistic precondition.
- No attacker-controlled role or key is required; the admin's own legitimate call creates the window.

---

### Recommendation

Change `_pause` from a setter to an accumulator, and add a separate `_unpause(flags)` that clears specific bits:

```solidity
function _pause(uint256 flags) internal virtual {
    $._pausedFlags |= flags;   // additive
}
function _unpause(uint256 flags) internal virtual {
    $._pausedFlags &= ~flags;  // selective clear
}
```

Alternatively, require `pause()` callers to explicitly pass the full desired bitmask and add a NatSpec warning that the call **replaces** all flags.

---

### Proof of Concept

```solidity
// 1. pauseAll() → _pausedFlags = 7
bridge.pauseAll();
assert(bridge.paused(PAUSED_DEPLOY_TOKEN));   // true

// 2. Admin intends to keep finTransfer+initTransfer paused
bridge.pause(PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER); // = pause(3)
assert(!bridge.paused(PAUSED_DEPLOY_TOKEN));  // TRUE — deployToken is now open

// 3. Call deployToken with a pre-issued valid signature
address token = bridge.deployToken(validSig, metadata);

// 4. Token is registered
assert(bridge.nearToEthToken(metadata.token) == token);
assert(bridge.isBridgeToken(token));
// finTransfer is still paused — minting deferred until unpause
```

### Citations

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L113-117)
```text
    function _pause(uint256 flags) internal virtual {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        $._pausedFlags = flags;
        emit Paused(_msgSender(), $._pausedFlags);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L52-55)
```text
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-349)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-550)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L552-557)
```text
    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```
