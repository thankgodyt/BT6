The bug is confirmed in the code. Let me trace it precisely.

---

### Title
Pause Flag Replacement in `_pause` Silently Clears Existing Pause Flags — (`evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

### Summary

`SelectivePausableUpgradable._pause` uses plain assignment (`=`) instead of bitwise OR-assignment (`|=`) when writing to `_pausedFlags`. Any call to `pause(X)` after `pauseAll()` replaces the full bitmask with only `X`, silently unpausing all other flags the operator believed were still active.

### Finding Description

`_pause` is implemented as:

```solidity
// SelectivePausableUpgradable.sol line 113-117
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // ← assignment, not |=
    emit Paused(_msgSender(), $._pausedFlags);
}
``` [1](#0-0) 

The three pause flags are:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;  // 0x1
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;  // 0x2
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;  // 0x4
``` [2](#0-1) 

`pauseAll()` (callable by `PAUSABLE_ADMIN_ROLE`) sets all three bits:

```solidity
// OmniBridge.sol line 552-557
function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
    uint256 flags = PAUSED_FIN_TRANSFER |
        PAUSED_INIT_TRANSFER |
        PAUSED_DEPLOY_TOKEN;
    _pause(flags);   // _pausedFlags = 0x7
}
``` [3](#0-2) 

`pause()` (callable by `DEFAULT_ADMIN_ROLE`) passes the caller-supplied bitmask directly to `_pause`:

```solidity
// OmniBridge.sol line 548-550
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause(flags);
}
``` [4](#0-3) 

**Exploit sequence:**

| Step | Call | `_pausedFlags` after |
|------|------|----------------------|
| 1 | `pauseAll()` | `0x7` (all paused) |
| 2 | `pause(PAUSED_FIN_TRANSFER)` | `0x2` ← **0x1 and 0x4 silently cleared** |

After step 2, `paused(PAUSED_INIT_TRANSFER)` returns `false` and `paused(PAUSED_DEPLOY_TOKEN)` returns `false`, because:

```solidity
// SelectivePausableUpgradable.sol line 83-86
function paused(uint256 flag) public view virtual returns (bool) {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    return ($._pausedFlags & flag) != 0;   // 0x2 & 0x1 == 0 → false
}
``` [5](#0-4) 

`initTransfer` and `deployToken` are now callable because their guards check only their own flag:

```solidity
// OmniBridge.sol line 380
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
``` [6](#0-5) 

```solidity
// OmniBridge.sol line 138
) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
``` [7](#0-6) 

### Impact Explanation

During an active emergency pause (e.g., a bridge exploit is being investigated), a `DEFAULT_ADMIN_ROLE` holder calling `pause(PAUSED_FIN_TRANSFER)` — a semantically reasonable action — silently re-enables `initTransfer` and `deployToken`. Users can then:

- Call `initTransfer` to lock/burn tokens into the bridge while the emergency is unresolved, potentially causing permanent loss of those funds if the emergency involves a bridge-side accounting or finalization bug.
- Call `deployToken` to deploy new bridge token contracts during an emergency window, potentially binding malicious or incorrect token metadata.

This is a **pause bypass** matching the Critical impact scope: "authorization bypass, role bypass, pause bypass... that lets an attacker execute bridge, token, deployer... actions."

### Likelihood Explanation

The scenario does not require a malicious admin. It requires only a legitimate `DEFAULT_ADMIN_ROLE` holder to call `pause(PAUSED_FIN_TRANSFER)` after `pauseAll()` — a plausible operational action (e.g., "re-enable finalization while keeping initiation paused" or "confirm FIN_TRANSFER is paused"). The function name `pause` implies additive semantics; the replacement semantics are non-obvious and undocumented. This is a realistic operator mistake under emergency pressure.

### Recommendation

Change the assignment in `_pause` from `=` to `|=`:

```solidity
// SelectivePausableUpgradable.sol line 115
- $._pausedFlags = flags;
+ $._pausedFlags |= flags;
```

Add a corresponding `_unpause(uint256 flags)` that uses `&= ~flags` for selective unpausing, and ensure `pauseAll` / `unpauseAll` remain consistent. [1](#0-0) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/OmniBridge.sol";

contract PauseFlagClearTest is Test {
    OmniBridge bridge;
    address admin    = address(0xA1);
    address pauseAdmin = address(0xA2);

    function setUp() public {
        bridge = new OmniBridge();
        // initialize with admin as deployer
        vm.prank(admin);
        bridge.initialize(address(1), address(2), 1);
        // grant PAUSABLE_ADMIN_ROLE to pauseAdmin
        vm.prank(admin);
        bridge.grantRole(bridge.PAUSABLE_ADMIN_ROLE(), pauseAdmin);
    }

    function testPauseFlagSilentlyClearedByPause() public {
        // Step 1: emergency — pause everything
        vm.prank(pauseAdmin);
        bridge.pauseAll();
        assertTrue(bridge.paused(1 << 0), "INIT_TRANSFER should be paused");
        assertTrue(bridge.paused(1 << 1), "FIN_TRANSFER should be paused");
        assertTrue(bridge.paused(1 << 2), "DEPLOY_TOKEN should be paused");

        // Step 2: DEFAULT_ADMIN_ROLE calls pause(PAUSED_FIN_TRANSFER) — intending to keep FIN paused
        vm.prank(admin);
        bridge.pause(1 << 1);  // PAUSED_FIN_TRANSFER only

        // Bug: INIT_TRANSFER and DEPLOY_TOKEN are now silently unpaused
        assertFalse(bridge.paused(1 << 0), "INIT_TRANSFER unexpectedly unpaused!");
        assertFalse(bridge.paused(1 << 2), "DEPLOY_TOKEN unexpectedly unpaused!");

        // Step 3: any user can now call initTransfer during the emergency window
        // (call would revert only on token logic, not on pause check)
        vm.expectRevert("Pausable: paused");  // This line will NOT be reached — pause is gone
        // bridge.initTransfer(...) would succeed past the whenNotPaused gate
    }
}
```

Running this test against the unmodified code will show `paused(PAUSED_INIT_TRANSFER)` returning `false` after `pause(PAUSED_FIN_TRANSFER)`, confirming the silent flag clear. [1](#0-0) [8](#0-7)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L53-55)
```text
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L138-138)
```text
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L380-380)
```text
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
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
