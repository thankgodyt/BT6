### Title
Selective Pause Flag Replacement Allows Inadvertent Pause Bypass on `finTransfer` - (File: `evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

---

### Summary

The `_pause(flags)` function in `SelectivePausableUpgradable.sol` **replaces** the entire `_pausedFlags` bitmask rather than ORing the new flags into it. As a result, any admin call to `pause(X)` silently clears all previously set pause bits not included in `X`. An attacker who monitors the mempool can exploit the window in which `PAUSED_FIN_TRANSFER` is inadvertently cleared to call `finTransfer` with a valid MPC signature, bypassing an active emergency pause.

---

### Finding Description

`SelectivePausableUpgradable._pause` is implemented as an assignment, not a bitwise OR:

```solidity
// SelectivePausableUpgradable.sol line 113-117
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // ← full replacement, not |=
    emit Paused(_msgSender(), $._pausedFlags);
}
``` [1](#0-0) 

`OmniBridge` exposes two separate pause entry points that both call `_pause`:

```solidity
// OmniBridge.sol lines 548-557
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause(flags);
}

function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
    uint256 flags = PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER | PAUSED_DEPLOY_TOKEN;
    _pause(flags);
}
``` [2](#0-1) 

The three independent pause flags are:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;   // 1
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;   // 2
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;   // 4
``` [3](#0-2) 

**Attack scenario:**

| Step | Admin action | `_pausedFlags` result |
|---|---|---|
| 1 | `pause(PAUSED_FIN_TRANSFER)` | `0x02` — finTransfer blocked |
| 2 | `pause(PAUSED_INIT_TRANSFER)` | `0x01` — **finTransfer silently unblocked** |

After step 2, `finTransfer` is no longer guarded by `whenNotPaused(PAUSED_FIN_TRANSFER)`:

```solidity
// OmniBridge.sol line 282
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
``` [4](#0-3) 

An attacker who holds a valid, unused MPC signature (obtained from a legitimate prior transfer) can call `finTransfer` in the same block as the admin's second `pause` call, or any time afterward, while the admin believes finalization is still blocked.

---

### Impact Explanation

`finTransfer` mints bridge tokens or transfers locked ERC-20/ETH/ERC-1155 assets to the recipient. If the admin paused `PAUSED_FIN_TRANSFER` because a security incident was discovered (e.g., a double-spend vector, a bug in token accounting, or a compromised nonce), the inadvertent unpausing allows any holder of a valid MPC signature to finalize transfers that the admin intended to block. Depending on the nature of the incident, this can result in unauthorized minting of bridged tokens or release of locked funds — a direct loss of bridged assets.

---

### Likelihood Explanation

The scenario is realistic: an admin responding to an incident would naturally first pause `finTransfer`, then separately pause `initTransfer` to stop new inflows. The `pause(flags)` API gives no indication that it replaces rather than accumulates flags. The `pauseAll()` helper avoids the bug, but its existence does not prevent the admin from using `pause()` individually. Any attacker monitoring the chain for the second `pause` transaction can immediately exploit the cleared flag.

---

### Recommendation

Change `_pause` to accumulate flags with bitwise OR, and add a corresponding `_unpause` that clears specific bits:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;          // accumulate, do not replace
    emit Paused(_msgSender(), $._pausedFlags);
}

function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags &= ~flags;
    emit Paused(_msgSender(), $._pausedFlags);
}
```

Expose `unpause(uint256 flags)` externally so admins can selectively clear individual pause bits without disturbing others.

---

### Proof of Concept

1. A security incident is detected; admin calls `pause(2)` (`PAUSED_FIN_TRANSFER`). `_pausedFlags = 0x02`. `finTransfer` reverts for all callers.
2. Admin decides to also halt new deposits and calls `pause(1)` (`PAUSED_INIT_TRANSFER`). `_pausedFlags = 0x01`. `PAUSED_FIN_TRANSFER` bit is now **cleared**.
3. Attacker, who previously initiated a cross-chain transfer and received a valid MPC-signed `TransferMessagePayload`, calls `finTransfer(signatureData, payload)`.
4. `whenNotPaused(PAUSED_FIN_TRANSFER)` checks `(_pausedFlags & 2) != 0` → `(1 & 2) = 0` → **not paused**. The call proceeds.
5. `completedTransfers[payload.destinationNonce]` is `false` (unused nonce). Signature verifies against `nearBridgeDerivedAddress`. Tokens are minted/transferred to the attacker's recipient address — bypassing the emergency pause. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L83-86)
```text
    function paused(uint256 flag) public view virtual returns (bool) {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        return ($._pausedFlags & flag) != 0;
    }
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-313)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-557)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```
