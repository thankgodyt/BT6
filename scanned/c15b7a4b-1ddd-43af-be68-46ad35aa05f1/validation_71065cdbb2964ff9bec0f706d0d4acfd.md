### Title
Selective Pause Overwrites All Flags (Assignment vs OR), Silently Re-enabling `finTransfer` / `ICustomMinter.mint` — (`evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

---

### Summary

`_pause` performs a full assignment of `_pausedFlags`, not a bitwise OR. Any call to `pause(subset)` after `pauseAll()` silently clears every bit not present in `subset`, re-enabling the corresponding functions — including `finTransfer` and its `ICustomMinter.mint` path.

---

### Finding Description

`_pause` in `SelectivePausableUpgradable.sol` writes:

```solidity
$._pausedFlags = flags;   // line 115 — assignment, not |=
``` [1](#0-0) 

`OmniBridge` exposes two pause entry-points with different role requirements:

```solidity
function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) { ... }  // sets 0b111
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(flags); }
``` [2](#0-1) 

The three flag constants are:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;   // 0b001
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;   // 0b010
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;   // 0b100
``` [3](#0-2) 

Call sequence that triggers the bug:

| Step | Call | `_pausedFlags` after |
|------|------|----------------------|
| 1 | `pauseAll()` | `0b111` (all paused) |
| 2 | `pause(PAUSED_INIT_TRANSFER)` | `0b001` (`FIN_TRANSFER` and `DEPLOY_TOKEN` **cleared**) |

After step 2, `finTransfer` passes its `whenNotPaused(PAUSED_FIN_TRANSFER)` guard and reaches:

```solidity
} else if (customMinters[payload.tokenAddress] != address(0)) {
    ICustomMinter(customMinters[payload.tokenAddress]).mint(
        payload.tokenAddress, payload.recipient, payload.amount
    );
``` [4](#0-3) 

---

### Impact Explanation

`finTransfer` still requires a valid ECDSA signature from `nearBridgeDerivedAddress`, so a random attacker cannot forge calls. However, the invariant broken here is **operational**: an emergency `pauseAll()` is supposed to halt all token flows until the situation is resolved. If `DEFAULT_ADMIN_ROLE` subsequently calls `pause(PAUSED_INIT_TRANSFER)` — a completely reasonable action to selectively re-restrict only outbound transfers — the emergency halt on `finTransfer` and `ICustomMinter.mint` is silently lifted. Any pending or replayed valid MPC-signed message can then execute minting that the protocol operators believed was blocked.

---

### Likelihood Explanation

This is not an admin-key-compromise scenario. It is an **inadvertent operational mistake** caused by a counterintuitive API: `pause` looks additive but is actually a full replacement. During an incident, operators under time pressure are likely to call `pause(PAUSED_INIT_TRANSFER)` to "add" a selective pause, not realising they are erasing the existing emergency state. The two roles (`PAUSABLE_ADMIN_ROLE` and `DEFAULT_ADMIN_ROLE`) may even be held by different people or multisigs, making the interaction harder to reason about.

---

### Recommendation

Change `_pause` to use bitwise OR so flags accumulate:

```solidity
// SelectivePausableUpgradable.sol
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;          // OR, not assignment
    emit Paused(_msgSender(), $._pausedFlags);
}
```

Provide a separate `_unpause(uint256 flags)` that clears specific bits:

```solidity
function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags &= ~flags;
    emit Unpaused(_msgSender(), $._pausedFlags);
}
```

Expose `unpause(uint256 flags)` (guarded by `DEFAULT_ADMIN_ROLE`) so selective un-pausing is explicit and auditable, and remove the ability to silently clear unrelated bits.

---

### Proof of Concept

```solidity
// Pseudocode unit test (local testnet, no mainnet interaction)
function test_pauseOverwriteClears_finTransfer() public {
    // Setup: grant roles, register a customMinter for tokenA
    bridge.grantRole(PAUSABLE_ADMIN_ROLE, alice);
    bridge.grantRole(DEFAULT_ADMIN_ROLE, bob);
    bridge.addCustomToken("near.token", tokenA, customMinter, 18);

    // Step 1: emergency full pause
    vm.prank(alice);
    bridge.pauseAll();
    assertEq(bridge.pausedFlags(), 0b111);
    assertTrue(bridge.paused(PAUSED_FIN_TRANSFER));

    // Step 2: admin selectively pauses only initTransfer
    vm.prank(bob);
    bridge.pause(PAUSED_INIT_TRANSFER);          // 0b001
    assertEq(bridge.pausedFlags(), 0b001);

    // Invariant violated: FIN_TRANSFER is no longer paused
    assertFalse(bridge.paused(PAUSED_FIN_TRANSFER));  // FAILS expectation

    // Step 3: attacker submits a valid (or previously obtained) MPC signature
    // finTransfer executes → ICustomMinter.mint runs despite emergency pause
    bridge.finTransfer(validSig, payload);       // succeeds, mints tokens
}
``` [1](#0-0) [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-283)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L331-336)
```text
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
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
