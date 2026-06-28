### Title
`removeCustomToken()` Permanently Freezes User Bridged Funds Without Supply Check - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol` exposes a `removeCustomToken()` admin function that deletes all token routing mappings without checking whether users hold outstanding token balances. After removal, any user who holds the affected token on EVM and calls `initTransfer()` to bridge back to NEAR will have their tokens silently locked inside the bridge contract with no path to finalization, resulting in permanent fund loss.

---

### Finding Description

`removeCustomToken()` unconditionally deletes four mappings for the given token address: [1](#0-0) 

After this call:
- `isBridgeToken[tokenAddress]` → `false`
- `ethToNearToken[tokenAddress]` → `""` (empty string)
- `nearToEthToken[...]` → `address(0)`
- `customMinters[tokenAddress]` → `address(0)`

When a user subsequently calls `initTransfer()` with the now-removed token address, the function evaluates three branches in order: [2](#0-1) 

Because both `customMinters[tokenAddress]` and `isBridgeToken[tokenAddress]` are now zero/false, execution falls through to the **else branch**: `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)`. The tokens are transferred into the bridge contract and locked there. The `InitTransfer` event is then emitted: [3](#0-2) 

The NEAR bridge receives this event via a prover and attempts to finalize the transfer by looking up the EVM token address in its own `token_address_to_id` mapping. Since the token was removed, the NEAR side has no corresponding mapping and cannot finalize the transfer. The user's tokens are permanently locked in the EVM bridge contract with no recovery mechanism.

Additionally, `removeCustomToken()` contains no guard preventing it from being called on tokens deployed via `deployToken()` (standard BridgeTokens). If called on a BridgeToken, the `initTransfer` burn path (`BridgeToken(tokenAddress).burn(msg.sender, amount)`) is bypassed, tokens are locked instead of burned, and the BridgeToken total supply diverges from the NEAR-side escrow — a critical escrow mis-accounting condition. [4](#0-3) 

---

### Impact Explanation

**Critical — Permanent freezing of bridged funds.**

Any user holding a custom-mapped ERC-20 token on EVM at the time `removeCustomToken()` is called loses the ability to bridge those tokens back to NEAR. Their tokens are locked inside the bridge contract with no withdrawal or redemption path. If the removed token is a BridgeToken (deployed via `deployToken`), the burn is skipped, creating a supply/escrow mismatch between the EVM and NEAR sides of the bridge.

---

### Likelihood Explanation

The admin has legitimate operational reasons to remove a custom token (e.g., token contract vulnerability, migration to a new address, regulatory action). The function provides no safeguard — no check on outstanding user balances, no check on the token's total supply held by the bridge, and no check that the token was actually added via `addCustomToken` rather than `deployToken`. Any routine administrative removal of a live token triggers the freeze for all current holders.

---

### Recommendation

1. **Supply check before removal:** Require that the bridge holds zero balance of the token (or that the BridgeToken total supply is zero) before allowing `removeCustomToken()` to proceed.
2. **Scope guard:** Add a check that the token being removed was registered via `addCustomToken` and is not a BridgeToken deployed via `deployToken`, or provide a separate removal path for each type.
3. **Redemption path:** If removal is necessary while supply is non-zero, implement a redemption function that allows users to recover their tokens directly from the bridge contract without requiring NEAR-side finalization.

---

### Proof of Concept

1. Admin calls `addCustomToken("usdc.near", usdcAddress, address(0), 6)` — USDC is registered as a custom bridge token.
2. User A calls `initTransfer(usdcAddress, 1000e6, 0, 0, "usera.near", "")` — 1000 USDC locked in bridge; NEAR side credits `usera.near` with 1000 USDC.
3. Admin calls `removeCustomToken(usdcAddress)` — all four mappings deleted.
4. User A, holding 1000 USDC on EVM (received via a prior `finTransfer`), calls `initTransfer(usdcAddress, 1000e6, 0, 0, "usera.near", "")`.
   - `customMinters[usdcAddress]` = `address(0)` → skip
   - `isBridgeToken[usdcAddress]` = `false` → skip
   - Else branch executes: `IERC20(usdcAddress).safeTransferFrom(userA, bridge, 1000e6)` — 1000 USDC locked in bridge.
   - `InitTransfer` event emitted with `tokenAddress = usdcAddress`.
5. NEAR bridge receives the event, looks up `usdcAddress` in `token_address_to_id` — mapping is gone, transfer cannot be finalized.
6. User A's 1000 USDC is permanently frozen inside the EVM bridge contract. [1](#0-0) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L120-127)
```text
    function removeCustomToken(
        address tokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delete isBridgeToken[tokenAddress];
        delete nearToEthToken[ethToNearToken[tokenAddress]];
        delete ethToNearToken[tokenAddress];
        delete customMinters[tokenAddress];
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-412)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```
