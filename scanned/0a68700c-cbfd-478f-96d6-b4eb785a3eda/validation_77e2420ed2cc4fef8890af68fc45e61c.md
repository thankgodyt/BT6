### Title
`removeCustomToken` permanently freezes in-flight bridged funds for custom-minter tokens — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.removeCustomToken` deletes the `isBridgeToken` and `customMinters` mappings for a token without checking for or protecting in-flight cross-chain transfers. Any NEAR→EVM transfer that was initiated before the removal but finalized after it will permanently fail on the EVM side, while the user's tokens on NEAR are already consumed. The funds are irrecoverable.

---

### Finding Description

`removeCustomToken` performs a hard delete of all four mappings that govern how a custom token is handled: [1](#0-0) 

`finTransfer` dispatches token delivery through a priority chain of checks: [2](#0-1) 

For a custom-minter token, `initTransfer` burns the user's tokens through the custom minter — the bridge contract itself never holds a balance: [3](#0-2) 

After `removeCustomToken` is called:
- `customMinters[tokenAddress]` → `address(0)` → the `customMinters` branch is skipped
- `isBridgeToken[tokenAddress]` → `false` → the `isBridgeToken` branch is skipped
- Execution falls through to `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)`

Because the bridge holds **zero balance** of the custom token (all supply was burned by the custom minter at `initTransfer` time), `safeTransfer` reverts. Every subsequent attempt by any relayer to call `finTransfer` for the in-flight transfer will also revert. The transfer is permanently undeliverable.

On the NEAR side, the user's tokens were already burned or locked when the outbound transfer was initiated, so there is no on-chain mechanism to recover them.

---

### Impact Explanation

Any user who initiated a NEAR→EVM transfer of a custom-minter token before `removeCustomToken` was called, but whose `finTransfer` has not yet been submitted or confirmed on EVM, permanently loses their bridged funds. The amount lost equals the full transfer amount for every such in-flight transfer at the time of removal. This is a direct, irreversible loss of bridged principal.

---

### Likelihood Explanation

`removeCustomToken` is a routine administrative operation with no guard against in-flight transfers. An admin performing a legitimate token migration, minter upgrade, or token deprecation would naturally call this function without auditing the mempool or NEAR pending-transfer state for outstanding transfers. Cross-chain finalization windows (15–18 minutes for Ethereum, longer for L2s) create a realistic race window. The probability of at least one in-flight transfer existing at the time of removal grows with bridge usage volume.

---

### Recommendation

Mirror the original report's recommended fix: introduce a "claim-only" (deprecated) state for custom tokens. When a token is removed, mark it as deprecated rather than deleting its mappings. In the deprecated state:
- `initTransfer` rejects new transfers for the token.
- `finTransfer` continues to honor the existing `customMinters` or `isBridgeToken` dispatch path for already-signed payloads.

Concretely, replace the hard `delete` in `removeCustomToken` with a flag (e.g., `isDeprecatedToken[tokenAddress] = true`) and gate `initTransfer` on `!isDeprecatedToken[tokenAddress]`, while leaving `customMinters` and `isBridgeToken` intact so `finTransfer` can still complete pending deliveries.

---

### Proof of Concept

1. Admin calls `addCustomToken(nearTokenId, tokenAddr, minterAddr, decimals)`.
2. User on NEAR initiates a transfer of 1000 units of the custom token to an EVM address. NEAR burns the tokens via the bridge; a signed `finTransfer` payload is queued for the relayer.
3. Admin calls `removeCustomToken(tokenAddr)` — a routine minter upgrade. This sets `isBridgeToken[tokenAddr] = false` and `customMinters[tokenAddr] = address(0)`.
4. Relayer submits `finTransfer(sig, payload)` on EVM.
   - `customMinters[tokenAddr]` is `address(0)` → skipped.
   - `isBridgeToken[tokenAddr]` is `false` → skipped.
   - Falls to `IERC20(tokenAddr).safeTransfer(recipient, 1000)`.
   - Bridge holds 0 balance → ERC20 transfer reverts → entire `finTransfer` reverts.
5. No relayer can ever successfully finalize this transfer. The user's 1000 tokens are permanently lost. [1](#0-0) [2](#0-1) [4](#0-3)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L331-355)
```text
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
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
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-412)
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
```
