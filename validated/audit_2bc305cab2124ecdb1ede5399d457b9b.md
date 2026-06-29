### Title
Removed Custom Tokens Can Still Be Bridged via `initTransfer` After `removeCustomToken` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` exposes `removeCustomToken` for admins to de-register a custom token from the bridge. However, `initTransfer` contains no check that the supplied `tokenAddress` is still registered (i.e., that `ethToNearToken[tokenAddress]` is non-empty). After removal, the token silently falls through to the native-lock path, tokens are locked in the contract, an `InitTransfer` event is emitted, and the NEAR side — whose registry is never updated — processes the transfer normally and mints/unlocks NEAR-side tokens for the caller.

### Finding Description

`removeCustomToken` clears all four EVM-side mappings for a token: [1](#0-0) 

After removal, `initTransfer` evaluates the token against three branches: [2](#0-1) 

Because `customMinters[tokenAddress]` is now `address(0)` and `isBridgeToken[tokenAddress]` is now `false`, the call falls through to the final `else` branch, which simply locks the tokens in the contract via `safeTransferFrom`. No check is made that `ethToNearToken[tokenAddress]` is non-empty (i.e., that the token is still registered). The `InitTransfer` event is then emitted normally: [3](#0-2) 

On the NEAR side, `fin_transfer_callback` receives the proof of this event. It looks up the token's decimals using the EVM address: [4](#0-3) 

Because `removeCustomToken` is an EVM-only operation and there is no corresponding NEAR-side removal function, `token_decimals` and `token_address_to_id` still contain the removed token's entry. `get_token_id` succeeds: [5](#0-4) 

The NEAR side then mints or unlocks NEAR-side tokens for the recipient, completing the transfer as if the token had never been removed.

### Impact Explanation

**Critical — balance manipulation and escrow mis-accounting.**

Before removal, `initTransfer` invokes the custom minter to *burn* EVM tokens, maintaining the cross-chain supply invariant. After removal, EVM tokens are merely *locked* in the bridge contract (supply not reduced), while the NEAR side still *mints* the corresponding NEAR tokens. The total cross-chain supply of the token inflates with every such transfer.

If the token was removed precisely because it is malicious (e.g., its contract allows the owner to mint arbitrary amounts), the attacker can:
1. Mint unlimited EVM tokens at zero cost.
2. Call `initTransfer` repeatedly.
3. Receive real NEAR-side tokens in return.
4. Drain the NEAR bridge's token reserves indefinitely.

There is no per-token pause mechanism; the only mitigation available to the admin is `pauseAll()`, which halts the entire bridge.

### Likelihood Explanation

**Medium.** The precondition is that `removeCustomToken` has been called — an admin action taken specifically because the token is problematic. The window of exploitation is unbounded: because there is no NEAR-side removal function, the NEAR registry retains the token mapping permanently, so the attack remains viable indefinitely after EVM-side removal. Any user (or the token's own deployer) can call `initTransfer` without any special privilege.

### Recommendation

Add a registration check at the top of `initTransfer` (and `initTransfer1155`) before any token movement occurs:

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    uint128 fee,
    uint128 nativeFee,
    string calldata recipient,
    string calldata message
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
+   if (tokenAddress != address(0)) {
+       require(
+           bytes(ethToNearToken[tokenAddress]).length > 0 ||
+           multiTokens[tokenAddress].tokenAddress != address(0),
+           "ERR_TOKEN_NOT_REGISTERED"
+       );
+   }
    ...
}
```

This mirrors the fix recommended in the referenced report: validate the whitelist entry before allowing the operation to proceed.

### Proof of Concept

1. Admin calls `addCustomToken("tok.near", tokenAddr, customMinter, 18)`.
2. Admin later calls `removeCustomToken(tokenAddr)` — all four EVM mappings are cleared.
3. Attacker (controlling the malicious token contract) mints `N` tokens to themselves.
4. Attacker calls `initTransfer(tokenAddr, N, 0, 0, "attacker.near", "")`.
   - `customMinters[tokenAddr]` == `address(0)` → first branch skipped.
   - `isBridgeToken[tokenAddr]` == `false` → second branch skipped.
   - `safeTransferFrom(attacker, bridge, N)` executes — tokens locked, not burned.
   - `InitTransfer` event emitted.
5. Relayer submits proof to NEAR `fin_transfer`.
6. NEAR `fin_transfer_callback` finds `token_decimals` entry (never removed), resolves NEAR token ID via `token_address_to_id` (never removed), and mints/unlocks NEAR tokens to `attacker.near`.
7. Attacker repeats from step 3, draining NEAR-side reserves.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-413)
```text
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

**File:** near/omni-bridge/src/lib.rs (L715-718)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```

**File:** near/omni-bridge/src/lib.rs (L1368-1375)
```rust
    pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
        if let OmniAddress::Near(token_account_id) = address {
            token_account_id.clone()
        } else {
            self.token_address_to_id
                .get(address)
                .near_expect(BridgeError::TokenNotRegistered)
        }
```
