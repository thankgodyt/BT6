### Title
Inadequate Validation in `removeCustomToken` Allows Permanent Freezing of In-Flight Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`removeCustomToken` in `OmniBridge.sol` atomically deletes all four token-routing mappings (`isBridgeToken`, `ethToNearToken`, `nearToEthToken`, `customMinters`) with no check for pending cross-chain transfers. If the function is called while a NEAR→EVM transfer is in-flight, the corresponding `finTransfer` call will permanently fail, freezing the user's already-burned NEAR-side tokens with no recovery path.

---

### Finding Description

`removeCustomToken` (lines 120–127) performs four unconditional `delete` operations:

```solidity
function removeCustomToken(address tokenAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    delete isBridgeToken[tokenAddress];
    delete nearToEthToken[ethToNearToken[tokenAddress]];
    delete ethToNearToken[tokenAddress];
    delete customMinters[tokenAddress];
}
``` [1](#0-0) 

`finTransfer` (lines 279–367) resolves the delivery path for incoming transfers using a priority chain:

1. `customMinters[payload.tokenAddress] != address(0)` → mint via custom minter
2. `isBridgeToken[payload.tokenAddress]` → mint via `IBridgeToken`
3. **Fallback**: `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` — transfer from contract's own ERC-20 balance [2](#0-1) 

After `removeCustomToken` is called, both checks (1) and (2) evaluate to false. The fallback `safeTransfer` is reached, but the contract holds **zero balance** of a mint/burn custom token — it was never locked, only minted on arrival. The `safeTransfer` reverts, and the transfer can never be finalized.

---

### Impact Explanation

A user who initiated a transfer from NEAR (burning tokens on the NEAR side) while the custom token was registered will have their funds permanently frozen:

- NEAR-side tokens are already burned/locked — irreversible.
- EVM-side `finTransfer` will always revert because the contract holds no token balance and the minting path is gone.
- Because the Solidity transaction reverts atomically, `completedTransfers[destinationNonce]` is rolled back, so the nonce is not consumed — but every subsequent retry also reverts for the same reason.
- There is no on-chain escape hatch: no refund mechanism, no fallback route, no way for the user to recover funds without admin re-registering the token.

This constitutes **permanent freezing of bridged funds**, matching the Critical impact tier.

---

### Likelihood Explanation

Custom tokens (e.g., USDC with a custom minter) are a supported and documented feature via `addCustomToken`. An admin may legitimately call `removeCustomToken` to deprecate a token (e.g., after a token migration or security incident) without auditing the NEAR-side mempool or pending transfer queue. The NEAR→EVM transfer pipeline has no on-chain visibility from the EVM contract, making it structurally impossible for the admin to know whether in-flight transfers exist at the time of removal. The likelihood is realistic for any production deprecation event.

---

### Recommendation

Before clearing a custom token's configuration:

1. **Add a pending-transfer guard**: Maintain a counter of in-flight transfers per token address (incremented on `initTransfer`, decremented on `finTransfer`). Require the counter to be zero before allowing removal.
2. **Two-step deprecation**: Introduce a "deprecated" flag that blocks new `initTransfer` calls for the token while still allowing `finTransfer` to complete existing in-flight transfers. Only allow full deletion after the in-flight count reaches zero.
3. **Grace period**: Emit a `TokenDeprecationScheduled` event and enforce a time-lock before the mappings are deleted, giving relayers time to finalize pending transfers.

---

### Proof of Concept

1. Admin calls `addCustomToken("token.near", tokenAddress, customMinterAddress, 6)`. [3](#0-2) 

2. User on NEAR calls `init_transfer` — tokens are burned on NEAR; a signed `TransferMessagePayload` is produced for EVM finalization.

3. Admin calls `removeCustomToken(tokenAddress)` — all four mappings are deleted. [1](#0-0) 

4. Relayer calls `finTransfer(signatureData, payload)` where `payload.tokenAddress = tokenAddress`:
   - Line 331: `customMinters[tokenAddress]` → `address(0)` → branch skipped.
   - Line 337: `isBridgeToken[tokenAddress]` → `false` → branch skipped.
   - Line 351: `IERC20(tokenAddress).safeTransfer(payload.recipient, payload.amount)` → contract balance is 0 → **reverts**. [2](#0-1) 

5. Every subsequent retry of step 4 also reverts. The user's NEAR-side tokens are permanently lost with no recovery path available to the user.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L88-118)
```text
    function addCustomToken(
        string calldata nearTokenId,
        address tokenAddress,
        address customMinter,
        uint8 originDecimals
    ) external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        isBridgeToken[tokenAddress] = true;
        ethToNearToken[tokenAddress] = nearTokenId;
        nearToEthToken[nearTokenId] = tokenAddress;
        customMinters[tokenAddress] = customMinter;

        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        deployTokenExtension(
            nearTokenId,
            tokenAddress,
            decimals,
            originDecimals
        );

        emit BridgeTypes.DeployToken(
            tokenAddress,
            nearTokenId,
            name,
            symbol,
            decimals,
            originDecimals
        );
    }
```

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
