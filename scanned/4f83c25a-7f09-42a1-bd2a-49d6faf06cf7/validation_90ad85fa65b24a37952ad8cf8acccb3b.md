### Title
`_pause` Overwrites All Pause Flags Instead of OR-ing, Enabling Unintended Pause Bypass — (`evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

### Summary

`_pause` performs a plain assignment (`$._pausedFlags = flags`) rather than a bitwise OR (`$._pausedFlags |= flags`). Any call to `pause(x)` silently clears every previously set pause bit that is not present in `x`. An admin who calls `pause(PAUSED_INIT_TRANSFER)` while `PAUSED_FIN_TRANSFER` is already set will unknowingly re-enable `finTransfer`, allowing a pending or subsequently submitted `finTransfer` to execute in a state the admin believed was still blocked.

### Finding Description

**Root cause — `SelectivePausableUpgradable.sol` line 115:**

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // ← plain assignment, not |=
    emit Paused(_msgSender(), $._pausedFlags);
}
``` [1](#0-0) 

The three pause constants are independent bits:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;   // 0x01
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;   // 0x02
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;   // 0x04
``` [2](#0-1) 

`OmniBridge.pause` is the only non-emergency entry point and passes the caller-supplied `flags` directly to `_pause`:

```solidity
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause(flags);
}
``` [3](#0-2) 

`finTransfer` is gated solely by `whenNotPaused(PAUSED_FIN_TRANSFER)`:

```solidity
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
``` [4](#0-3) 

**Concrete call sequence:**

| Step | Call | `_pausedFlags` after |
|------|------|----------------------|
| 1 | `pause(PAUSED_FIN_TRANSFER)` | `0x02` |
| 2 | `pause(PAUSED_INIT_TRANSFER)` | `0x01` ← `PAUSED_FIN_TRANSFER` silently cleared |
| 3 | `finTransfer(...)` | succeeds — `0x01 & 0x02 == 0` |

Step 2 is a natural admin action: after pausing `finTransfer` during an incident, the admin decides to also pause `initTransfer`. The function name and signature give no indication that this replaces rather than augments the existing flags.

Note that `pauseAll` correctly computes the combined mask before calling `_pause`, but it is a separate function and does not fix the underlying defect in `_pause` itself. [5](#0-4) 

### Impact Explanation

An attacker holding a valid `finTransfer` signature (a legitimately signed cross-chain transfer payload from `nearBridgeDerivedAddress`) can finalize a bridge transfer — minting tokens or releasing escrowed assets — in a state where the admin believed `finTransfer` was paused. This is an unauthorized finalization of a bridge transfer, directly matching the "pause bypass enabling admin-equivalent action" critical impact.

### Likelihood Explanation

The admin mistake is highly probable: the `pause(uint256 flags)` API strongly implies additive semantics (pause *these* flags), not replacement semantics. Any operator who calls `pause` twice with different single-bit arguments will trigger this. No social engineering is required; the attacker only needs to observe on-chain state (or the mempool) and submit or re-submit a valid `finTransfer` after the second `pause` call lands.

### Recommendation

Change `_pause` to use bitwise OR:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;          // accumulate, never clear
    emit Paused(_msgSender(), $._pausedFlags);
}
```

Introduce a separate `_unpause(uint256 flags)` that clears specific bits (`$._pausedFlags &= ~flags`) for intentional unpausing.

### Proof of Concept

```solidity
// Foundry test (pseudo-code)
function test_pauseOverwrite() public {
    // Admin pauses finTransfer
    bridge.pause(PAUSED_FIN_TRANSFER);
    assertEq(bridge.pausedFlags(), PAUSED_FIN_TRANSFER);

    // Admin also wants to pause initTransfer — natural second call
    bridge.pause(PAUSED_INIT_TRANSFER);

    // PAUSED_FIN_TRANSFER is now silently cleared
    assertEq(bridge.pausedFlags(), PAUSED_INIT_TRANSFER); // 0x01, not 0x03

    // finTransfer succeeds despite admin believing it was paused
    bridge.finTransfer(validSig, validPayload); // does not revert
}
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L53-55)
```text
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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
