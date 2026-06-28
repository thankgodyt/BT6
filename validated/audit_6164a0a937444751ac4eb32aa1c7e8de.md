### Title
Silent `ICustomMinter.mint` on Codeless Address Permanently Consumes Nonce Without Minting Tokens — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` calls `ICustomMinter(customMinters[payload.tokenAddress]).mint(...)` — a **void function** — without verifying that the custom minter address contains deployed bytecode. In Solidity 0.8.x, a high-level call to a void function on a codeless address silently returns success. Because the destination nonce is marked used *before* the call and `FinTransfer` is emitted *after* it, the transfer is permanently finalized with no tokens delivered to the recipient.

---

### Finding Description

In `finTransfer`, the custom minter branch executes at lines 331–336:

```solidity
} else if (customMinters[payload.tokenAddress] != address(0)) {
    ICustomMinter(customMinters[payload.tokenAddress]).mint(
        payload.tokenAddress,
        payload.recipient,
        payload.amount
    );
``` [1](#0-0) 

`ICustomMinter.mint` is declared as a void function with no return value: [2](#0-1) 

Solidity 0.8.x does **not** insert an `extcodesize` check before high-level calls. When the EVM executes a `CALL` to an address with no deployed bytecode, it returns `(success=1, returndata="")`. Because `mint` returns nothing, Solidity does not attempt to decode the return data and does not revert. The call appears to succeed.

The nonce is marked used at line 287 — **before** the mint call: [3](#0-2) 

`FinTransfer` is emitted at line 359 — **after** the mint call: [4](#0-3) 

Both state changes are permanent and irrecoverable.

The same pattern applies to `ICustomMinter.burn` in `initTransfer` (lines 400–403): if the custom minter has no code, the burn call silently succeeds *after* tokens have already been transferred to the dead address via `safeTransferFrom`, locking them permanently. [5](#0-4) 

---

### Impact Explanation

If the registered custom minter address has no deployed code at the time `finTransfer` is called:

- The destination nonce is **permanently consumed** — it cannot be reused.
- `FinTransfer` is emitted, signaling successful finalization to all observers and the NEAR side.
- **Zero tokens** are minted to `payload.recipient`.
- The user's bridged funds are **permanently lost** with no recovery path.

This is a direct, irreversible loss of bridged funds — Critical impact under the allowed scope (balance manipulation / escrow mis-accounting).

---

### Likelihood Explanation

The custom minter address is set by admin via `addCustomToken`. For the address to be codeless at call time:

1. On EVM chains **without EIP-6780** (pre-Cancun forks, or non-Ethereum L2s the bridge targets), a custom minter contract with a `selfdestruct` function can have its code removed by whoever controls the minter — without requiring the bridge admin to act.
2. An admin error registering an EOA or an undeployed CREATE2 address as the custom minter produces the same codeless state from day one.
3. A CREATE2-deployed custom minter can be self-destructed and the address left empty while the bridge mapping still points to it.

The NEAR Omni Bridge targets multiple EVM chains beyond mainnet Ethereum, so EIP-6780 protections are not universally applicable. Likelihood is **low-medium**.

---

### Recommendation

**Short term:** Before calling `ICustomMinter.mint` or `ICustomMinter.burn`, verify that the custom minter address contains deployed code:

```solidity
address minter = customMinters[payload.tokenAddress];
require(minter.code.length > 0, "ERR_MINTER_NOT_CONTRACT");
ICustomMinter(minter).mint(payload.tokenAddress, payload.recipient, payload.amount);
```

**Long term:** Apply the same existence check inside `addCustomToken` at registration time, so a codeless address can never be stored in `customMinters` in the first place. [6](#0-5) 

---

### Proof of Concept

1. Admin calls `addCustomToken("near.token", tokenAddr, minterAddr, 18)` where `minterAddr` is a deployed contract with a `selfdestruct` function (on a chain without EIP-6780).
2. `minterAddr` is self-destructed, leaving the address codeless. The `customMinters[tokenAddr]` mapping still holds `minterAddr`.
3. A user initiates a NEAR→EVM transfer for `tokenAddr`. The MPC network signs the payload.
4. A relayer calls `finTransfer(sig, payload)` where `payload.tokenAddress = tokenAddr`.
5. `completedTransfers[payload.destinationNonce] = true` is set (line 287) — nonce consumed.
6. `ICustomMinter(minterAddr).mint(...)` is called. The EVM `CALL` to the codeless address returns `(1, "")`. Since `mint` is void, Solidity does not revert.
7. `FinTransfer` is emitted (line 359) — transfer appears finalized.
8. `payload.recipient` receives **zero tokens**. The nonce is permanently consumed. Funds are lost with no recourse.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-288)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L359-367)
```text
        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-403)
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
```

**File:** evm/src/common/ICustomMinter.sol (L5-6)
```text
    function mint(address token, address to, uint128 amount) external;
    function burn(address token, uint128 amount) external;
```
