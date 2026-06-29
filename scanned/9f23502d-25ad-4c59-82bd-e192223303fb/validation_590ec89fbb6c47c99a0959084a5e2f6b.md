The vulnerability claim is concrete and verifiable. Let me trace through the exact code.

**`_pause` in `SelectivePausableUpgradable.sol` line 115 uses direct assignment:**

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;   // ← assignment, not |=
    emit Paused(_msgSender(), $._pausedFlags);
}
```

**`pauseAll()` sets `_pausedFlags = 7`:** [1](#0-0) 

**`pause(flags)` replaces `_pausedFlags` entirely:** [2](#0-1) 

**`paused(flag)` checks via bitwise AND:** [3](#0-2) 

**`finTransfer` is gated by `whenNotPaused(PAUSED_FIN_TRANSFER)`:** [4](#0-3) 

The call sequence `pauseAll()` → `pause(1)` produces:
- After `pauseAll()`: `_pausedFlags = 7` (binary `111`)
- After `pause(1)`: `_pausedFlags = 1` (binary `001`)
- `paused(PAUSED_FIN_TRANSFER)` = `(1 & 2) != 0` = **false** → `finTransfer` is now callable
- `paused(PAUSED_DEPLOY_TOKEN)` = `(1 & 4) != 0` = **false** → `deployToken` is now callable

There is no `unpause()` function in the contract; `pause()` is the only mechanism to modify pause state, making this assignment-vs-OR confusion the sole control path. [5](#0-4) 

---

### Title
`_pause` Overwrites All Pause Flags on Each Call, Allowing `pause(PAUSED_INIT_TRANSFER)` to Silently Unpause `finTransfer` and `deployToken` After `pauseAll()` — (`evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

### Summary
`_pause(uint256 flags)` uses direct assignment (`$._pausedFlags = flags`) rather than bitwise OR (`$._pausedFlags |= flags`). Any call to `pause(subset)` after `pauseAll()` replaces the full pause bitmap with only the subset, silently clearing all other pause bits. A DEFAULT_ADMIN_ROLE holder calling `pause(PAUSED_INIT_TRANSFER)` after an emergency `pauseAll()` reduces `_pausedFlags` from `7` to `1`, re-enabling `finTransfer` (flag `2`) and `deployToken` (flag `4`).

### Finding Description
`SelectivePausableUpgradable._pause` at line 115 performs:

```solidity
$._pausedFlags = flags;
```

`OmniBridge.pauseAll()` calls `_pause(7)`, setting all three bits. `OmniBridge.pause(flags)` is callable by any `DEFAULT_ADMIN_ROLE` holder and calls `_pause(flags)` with whatever value is passed. Passing `PAUSED_INIT_TRANSFER` (value `1`) replaces `_pausedFlags` with `1`, clearing bits for `PAUSED_FIN_TRANSFER` (`2`) and `PAUSED_DEPLOY_TOKEN` (`4`).

There is no `unpause()` function; `pause()` doubles as both the pause and the state-setter, making the overwrite semantics non-obvious and dangerous. The `paused(flag)` check uses `($._pausedFlags & flag) != 0`, so after the overwrite `paused(PAUSED_FIN_TRANSFER)` returns `false` and `whenNotPaused(PAUSED_FIN_TRANSFER)` passes. [5](#0-4) [6](#0-5) 

### Impact Explanation
`finTransfer` verifies an ECDSA signature against `nearBridgeDerivedAddress` and then mints or transfers tokens to `payload.recipient`. Once the pause gate is bypassed, any valid MPC-signed payload (including ones that were legitimately signed before the emergency halt) can be submitted and will execute token mints or transfers. This constitutes a pause bypass enabling acceptance of MPC signatures for `finTransfer` when the system was intended to be fully halted, directly matching the Critical impact category: *"Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass."* [7](#0-6) 

### Likelihood Explanation
The scenario does not require a malicious actor. During incident response, a DEFAULT_ADMIN_ROLE holder may reasonably call `pause(PAUSED_INIT_TRANSFER)` to selectively pause inbound transfers while believing the full emergency pause remains in effect. The function name `pause` implies additive semantics; the replacement semantics are not documented or enforced. The two roles (`PAUSABLE_ADMIN_ROLE` and `DEFAULT_ADMIN_ROLE`) may be held by different keyholders or multisigs acting independently, making the race condition realistic.

### Recommendation
Change `_pause` to use bitwise OR so that calling `pause(flags)` only adds bits, never removes them:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;          // additive
    emit Paused(_msgSender(), $._pausedFlags);
}
```

Add a separate `_unpause(uint256 flags)` that clears specific bits:

```solidity
function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags &= ~flags;         // selective clear
    emit Unpaused(_msgSender(), $._pausedFlags);
}
```

Expose a corresponding `unpause(uint256 flags)` on `OmniBridge` gated by `DEFAULT_ADMIN_ROLE`. This separates the concern of adding pauses from removing them and eliminates the silent-overwrite hazard.

### Proof of Concept

```solidity
// Deploy OmniBridge, grant roles, initialize
omniBridge.initialize(tokenImpl, nearDerived, chainId);

// Step 1: emergency halt
vm.prank(pausableAdmin);
omniBridge.pauseAll();
assertEq(omniBridge.pausedFlags(), 7);
assertTrue(omniBridge.paused(PAUSED_FIN_TRANSFER));   // ✓ paused

// Step 2: DEFAULT_ADMIN_ROLE "pauses" only initTransfer
vm.prank(defaultAdmin);
omniBridge.pause(PAUSED_INIT_TRANSFER);               // pause(1)
assertEq(omniBridge.pausedFlags(), 1);                // _pausedFlags = 1, not 7

// Step 3: finTransfer gate is now open
assertFalse(omniBridge.paused(PAUSED_FIN_TRANSFER));  // ✗ NOT paused — bug

// Step 4: submit a valid MPC-signed finTransfer payload
vm.prank(anyone);
omniBridge.finTransfer(validSig, payload);            // succeeds — emergency halt bypassed
``` [5](#0-4) [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L50-55)
```text
    bytes32 public constant PAUSABLE_ADMIN_ROLE =
        keccak256("PAUSABLE_ADMIN_ROLE");
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
