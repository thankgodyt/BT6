### Title
Pause Flag Full-Replacement Silently Clears Other Active Pause Bits, Enabling Pause Bypass — (`File: evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

### Summary

`SelectivePausableUpgradable._pause(uint256 flags)` performs a full assignment (`$._pausedFlags = flags`) rather than a bitwise OR. This is the structural analog of the Winnables `setRole()` bug: just as that function could only set bits (never clear them), this function can only replace the entire bitmask — it cannot selectively add a flag without erasing all previously set flags. An admin attempting to add a new pause flag (e.g., `PAUSED_INIT_TRANSFER`) while `PAUSED_FIN_TRANSFER` is already active will silently clear `PAUSED_FIN_TRANSFER`, creating an unintended window where `finTransfer` is callable by any relayer or attacker.

### Finding Description

`_pause` in `SelectivePausableUpgradable.sol` writes the caller-supplied `flags` value directly to storage:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // full replacement, not |= or &=
    emit Paused(_msgSender(), $._pausedFlags);
}
``` [1](#0-0) 

`OmniBridge.pause(uint256 flags)` is the only public entry point for selective pausing and delegates directly to `_pause`:

```solidity
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause(flags);
}
``` [2](#0-1) 

The three independent pause flags are:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;
``` [3](#0-2) 

Because `_pause` replaces the entire word, calling `pause(PAUSED_INIT_TRANSFER)` when `PAUSED_FIN_TRANSFER` is already set writes `0x01` to `_pausedFlags`, clearing bit 1 and silently unpausing `finTransfer`. The `whenNotPaused` modifier then passes for `finTransfer`:

```solidity
function paused(uint256 flag) public view virtual returns (bool) {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    return ($._pausedFlags & flag) != 0;
}
``` [4](#0-3) 

### Impact Explanation

During a security incident the admin pauses `finTransfer` (e.g., to halt all incoming cross-chain completions). If the admin subsequently calls `pause(PAUSED_INIT_TRANSFER)` to also halt outgoing transfers, the full-replacement write clears `PAUSED_FIN_TRANSFER`. Any relayer or attacker holding a valid, previously-unused MPC-signed `TransferMessagePayload` can immediately call `finTransfer` and mint or unlock bridged tokens on the EVM side — exactly the action the admin was trying to block. This constitutes a **pause bypass** enabling unauthorized finalization of cross-chain transfers and potential loss of bridged funds.

### Likelihood Explanation

The scenario is realistic: multi-step incident response (pause one function, then another) is a standard operational pattern. The bug is silent — no revert, no warning — and the emitted `Paused` event shows only the new flags value, making it easy to miss that a previously-set flag was cleared. Any admin who does not manually compute the bitwise union before calling `pause` will trigger this.

### Recommendation

Change `_pause` to use bitwise OR for setting flags and provide a separate `_unpause` that uses bitwise AND-NOT for clearing:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = $._pausedFlags | flags;   // additive
    emit Paused(_msgSender(), $._pausedFlags);
}

function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = $._pausedFlags & ~flags;  // selective clear
    emit Unpaused(_msgSender(), $._pausedFlags);
}
```

Expose `unpause(uint256 flags)` as the public counterpart to `pause(uint256 flags)` so that each flag can be independently toggled without affecting others.

### Proof of Concept

1. Admin calls `pause(PAUSED_FIN_TRANSFER)` → `_pausedFlags = 0x02`. `finTransfer` is blocked.
2. Admin calls `pause(PAUSED_INIT_TRANSFER)` → `_pause(0x01)` executes `$._pausedFlags = 0x01`. `_pausedFlags` is now `0x01`, clearing bit 1.
3. `paused(PAUSED_FIN_TRANSFER)` returns `(0x01 & 0x02) != 0` → `false`. `finTransfer` is no longer paused.
4. Attacker calls `finTransfer(signature, payload)` with a valid MPC-signed payload. The `whenNotPaused(PAUSED_FIN_TRANSFER)` modifier passes, tokens are minted/unlocked to the attacker's recipient address. [1](#0-0) [5](#0-4)

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
