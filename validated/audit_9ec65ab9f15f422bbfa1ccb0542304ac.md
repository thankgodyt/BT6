The code is confirmed as described. Let me verify the key facts:

1. `_pause` at line 115 uses `=` (assignment), not `|=` (OR): [1](#0-0) 
2. `pause(uint256 flags)` is exposed to `DEFAULT_ADMIN_ROLE` and calls `_pause` directly: [2](#0-1) 
3. `finTransfer` is guarded by `whenNotPaused(PAUSED_FIN_TRANSFER)`: [3](#0-2) 
4. There is no `unpause(flags)` function — the only mechanism to change pause state is `pause(flags)` (full replacement) and `pauseAll()`: [4](#0-3) 
5. The three flags are independent bits: [5](#0-4) 

The bug is real and the exploit path is concrete. The attacker is an unprivileged external user who holds a valid, unused MPC-signed `TransferMessagePayload` (a normal precondition for any pending cross-chain transfer). The admin's two sequential `pause()` calls — each individually reasonable — inadvertently clear `PAUSED_FIN_TRANSFER`, and the attacker can then call `finTransfer` to mint/transfer assets the admin intended to block. This maps directly to the allowed critical impact of a **pause bypass enabling unauthorized bridge execution**.

---

Audit Report

## Title
Selective Pause Flag Replacement Silently Clears Active Pause Bits, Enabling Pause Bypass on `finTransfer` - (File: `evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

## Summary
`SelectivePausableUpgradable._pause` unconditionally replaces `_pausedFlags` with the supplied value instead of ORing new bits in. Any admin call to `pause(X)` silently clears all previously set pause bits not present in `X`. An attacker holding a valid, unused MPC-signed `TransferMessagePayload` can call `finTransfer` in the window after the second admin `pause()` call inadvertently clears `PAUSED_FIN_TRANSFER`, bypassing an active emergency pause and minting or releasing bridged assets.

## Finding Description
`_pause` performs a full assignment at line 115:

```solidity
// SelectivePausableUpgradable.sol L113-117
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;   // ← replaces, does not accumulate
    emit Paused(_msgSender(), $._pausedFlags);
}
```

`OmniBridge` exposes `pause(uint256 flags)` (restricted to `DEFAULT_ADMIN_ROLE`) which calls `_pause` directly, and `pauseAll()` (restricted to `PAUSABLE_ADMIN_ROLE`) which also calls `_pause` with all three flags ORed together. There is no `unpause` function; the only mechanism to modify pause state is through these two entry points.

Because `_pause` replaces the entire bitmask, the following admin sequence:

1. `pause(PAUSED_FIN_TRANSFER)` → `_pausedFlags = 0x02`
2. `pause(PAUSED_INIT_TRANSFER)` → `_pausedFlags = 0x01` (**`PAUSED_FIN_TRANSFER` bit cleared**)

leaves `finTransfer` unguarded. The `whenNotPaused(PAUSED_FIN_TRANSFER)` modifier checks `(_pausedFlags & 2) != 0`; after step 2 this evaluates to `(1 & 2) = 0`, so the modifier does not revert.

An attacker who monitors the mempool for the second `pause()` transaction can immediately call `finTransfer(signatureData, payload)` with any valid, unused MPC-signed payload. The nonce check (`completedTransfers[payload.destinationNonce]`) only prevents replay of already-finalized transfers; a fresh nonce passes. Signature verification against `nearBridgeDerivedAddress` passes because the signature was legitimately issued by the MPC for a real cross-chain transfer. The call proceeds to mint bridge tokens or transfer locked ERC-20/ETH/ERC-1155 assets to the attacker's recipient.

## Impact Explanation
This is a **pause bypass** enabling unauthorized execution of `finTransfer`, which mints bridge tokens (`IBridgeToken.mint`) or releases locked ERC-20/ETH/ERC-1155 funds. If the admin paused `PAUSED_FIN_TRANSFER` in response to a security incident (double-spend vector, accounting bug, compromised nonce range), the inadvertent unpausing allows any holder of a valid MPC signature to finalize transfers the admin intended to block — resulting in unauthorized minting or release of bridged assets. This matches the critical allowed impact: *pause bypass that lets an attacker execute bridge actions*, and *unauthorized minting or loss of bridged funds*.

## Likelihood Explanation
The scenario is operationally realistic. An incident responder would naturally first pause `finTransfer` to stop outflows, then separately pause `initTransfer` to stop new inflows. The `pause(flags)` API name implies accumulation, not replacement; nothing in the function signature or NatDoc warns that it clears existing bits. `pauseAll()` avoids the bug but does not prevent use of `pause()` individually. The attacker requires only a valid, unused MPC-signed payload — a normal precondition for any user with a pending cross-chain transfer. The exploit window opens the moment the second `pause()` transaction is confirmed and remains open indefinitely until the admin notices and calls `pauseAll()` or `pause(PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER)`.

## Recommendation
Change `_pause` to accumulate flags with bitwise OR, and introduce a dedicated `_unpause` that clears specific bits:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;
    emit Paused(_msgSender(), $._pausedFlags);
}

function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags &= ~flags;
    emit Unpaused(_msgSender(), $._pausedFlags);
}
```

Expose `unpause(uint256 flags)` externally (with appropriate role restriction) so admins can selectively clear individual pause bits without disturbing others. Update `pauseAll()` if a corresponding `unpauseAll()` is needed.

## Proof of Concept
1. Deploy `OmniBridge`. Grant `DEFAULT_ADMIN_ROLE` to `admin`.
2. A user initiates a cross-chain transfer; the NEAR MPC issues a signed `TransferMessagePayload` with `destinationNonce = N`. The user (or attacker) retains `(signatureData, payload)` without calling `finTransfer`.
3. A security incident is detected. `admin` calls `pause(2)` (`PAUSED_FIN_TRANSFER`). `_pausedFlags = 0x02`. `finTransfer` reverts for all callers.
4. `admin` calls `pause(1)` (`PAUSED_INIT_TRANSFER`) to also halt new deposits. `_pausedFlags = 0x01`. `PAUSED_FIN_TRANSFER` bit is silently cleared.
5. Attacker calls `finTransfer(signatureData, payload)`.
   - `whenNotPaused(PAUSED_FIN_TRANSFER)`: `(0x01 & 0x02) = 0` → **not paused, passes**.
   - `completedTransfers[N]` is `false` → passes.
   - `ECDSA.recover(hashed, signatureData) == nearBridgeDerivedAddress` → passes.
   - Tokens are minted/transferred to `payload.recipient` — emergency pause bypassed.

A Foundry test can reproduce this in under 20 lines: deploy the contract, call `pause(2)`, call `pause(1)`, assert `paused(PAUSED_FIN_TRANSFER)` returns `false`, then call `finTransfer` with a pre-signed payload and assert it succeeds.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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
