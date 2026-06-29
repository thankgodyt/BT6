### Title
Silent Success on Non-Existent ERC1155 Contract Enables Unauthorized NEAR Token Minting — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` makes a high-level call to `IERC1155(tokenAddress).safeTransferFrom(...)`, which returns `void`. In Solidity, a high-level call to a void-returning function on a non-existent (never-deployed or self-destructed) contract address silently returns success — no revert, no tokens transferred. Because `logMetadata1155` is fully permissionless and performs no on-chain call to the ERC1155 contract, an attacker can register any address (including a non-existent one) as an ERC1155 token, then call `initTransfer1155` to emit a legitimate-looking `InitTransfer` event without locking any real tokens. The NEAR side, which trusts the EVM event log as proof of locked funds, will mint bridged tokens to the attacker's recipient.

---

### Finding Description

`logMetadata1155` is permissionless and stores the `(tokenAddress, tokenId) → deterministicToken` mapping without making any call to the ERC1155 contract: [1](#0-0) 

It emits `LogMetadata(deterministicToken, ...)`, which the NEAR side uses to register the token. No existence check is performed on `tokenAddress`.

`initTransfer1155` then calls:

```solidity
IERC1155(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    tokenId,
    amount,
    ""
);
``` [2](#0-1) 

`IERC1155.safeTransferFrom` is declared as returning `void`:

```solidity
// OpenZeppelin IERC1155 — returns nothing
function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
```

When Solidity makes a high-level call to a void-returning function on an address with no deployed bytecode, the EVM CALL opcode returns `(success=true, returndata=0x)`. Because the function signature declares no return value, Solidity performs no ABI-decode and treats the call as successful. No revert is triggered.

This is in direct contrast to the `SafeERC20` path used for ERC20 tokens, which in OpenZeppelin v5 calls `Address.functionCall` → `verifyCallResultFromTarget`, which explicitly checks `target.code.length == 0` when `returndata.length == 0` and reverts with `AddressEmptyCode`: [3](#0-2) 

No equivalent guard exists for the ERC1155 path.

After the silent no-op `safeTransferFrom`, execution continues normally: [4](#0-3) 

The `InitTransfer` event is emitted with `tokenAddress = deterministicToken`, `amount`, and the attacker's NEAR recipient. The NEAR-side prover verifies the event log via light client or Wormhole VAA — both of which confirm the event was genuinely emitted on-chain. The NEAR bridge then mints the corresponding bridged tokens to the attacker's recipient.

The same silent-success pattern also exists in `finTransfer` for the ERC1155 path: [5](#0-4) 

If `multiToken.tokenAddress` is a non-existent contract, the `safeTransferFrom` call succeeds silently, the destination nonce is permanently consumed, and the recipient receives nothing — permanently freezing the bridged funds.

The `IBridgeToken.mint` and `ICustomMinter.mint` interfaces also return void: [6](#0-5) [7](#0-6) 

These are also vulnerable in `finTransfer` if the registered contract is non-existent, though those paths require prior admin registration.

---

### Impact Explanation

**Critical.** An unprivileged attacker can:

1. Call `logMetadata1155(nonExistentAddress, tokenId)` — permissionless, no on-chain call to the ERC1155 contract, always succeeds.
2. Call `initTransfer1155(nonExistentAddress, tokenId, amount, 0, nativeFee, "near:attacker.near", "")` — the `safeTransferFrom` to the non-existent contract silently succeeds, `InitTransfer` is emitted.
3. The NEAR prover verifies the genuine on-chain event and mints `amount` of the bridged token to `attacker.near`.

No real ERC1155 tokens are ever locked. The attacker mints unbacked bridged tokens on NEAR at will, draining the economic value of the bridge's token supply. This constitutes **unauthorized minting** and **balance/escrow mis-accounting** of bridged funds.

The `finTransfer` ERC1155 path additionally enables **permanent freezing** of in-flight funds: if `multiToken.tokenAddress` is non-existent at finalization time, the destination nonce is consumed and the recipient receives nothing, with no recovery path.

---

### Likelihood Explanation

**High.** Both `logMetadata1155` and `initTransfer1155` are fully permissionless — no role, no admin approval, no whitelist. The attacker only needs to supply a non-existent address and pay the `nativeFee` in ETH (a negligible cost). The attack is repeatable with different `tokenId` values to generate distinct deterministic token addresses. No front-running, no key compromise, and no external dependency failure is required.

---

### Recommendation

1. **Add a contract existence check in `initTransfer1155`** before calling `safeTransferFrom`. Use OpenZeppelin's `Address.isContract` (or inline `tokenAddress.code.length > 0`) to revert if the ERC1155 contract has no bytecode.

2. **Add a contract existence check in `logMetadata1155`** by making at least one read call to the ERC1155 contract (e.g., `IERC1155(tokenAddress).supportsInterface(type(IERC1155).interfaceId)`) so that registration of non-existent contracts reverts.

3. **Wrap ERC1155 calls in `finTransfer`** with a similar existence guard, or use a helper analogous to `SafeERC20` that checks `target.code.length` before dispatching.

4. **Wrap `IBridgeToken.mint` and `ICustomMinter.mint` calls** with `Address.functionCall` or equivalent to ensure the target has code before dispatching.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

// Attacker EOA calls these two functions in sequence.
// nonExistentERC1155 = any address with no deployed bytecode (e.g. address(0xdead))

// Step 1: Register the fake ERC1155 token (permissionless, no on-chain call to nonExistentERC1155)
OmniBridge.logMetadata1155(nonExistentERC1155, tokenId);
// → emits LogMetadata(deterministicToken, ...) → NEAR registers the token

// Step 2: Initiate transfer — safeTransferFrom on non-existent contract silently succeeds
OmniBridge.initTransfer1155{value: nativeFee}(
    nonExistentERC1155,
    tokenId,
    amount,   // e.g. 1_000_000e18
    0,        // fee
    nativeFee,
    "near:attacker.near",
    ""
);
// → IERC1155(nonExistentERC1155).safeTransferFrom(...) returns success (no code, void return)
// → emits InitTransfer(attacker, deterministicToken, nonce, amount, ...)
// → NEAR prover verifies event, mints amount tokens to attacker.near
// → No real ERC1155 tokens were ever locked
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-464)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L480-490)
```text
        emit BridgeTypes.InitTransfer(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/common/IBridgeToken.sol (L5-11)
```text
    function mint(address account, uint256 value) external;

    function mint(
        address account,
        uint256 value,
        bytes memory message
    ) external;
```

**File:** evm/src/common/ICustomMinter.sol (L5-6)
```text
    function mint(address token, address to, uint128 amount) external;
    function burn(address token, uint128 amount) external;
```
