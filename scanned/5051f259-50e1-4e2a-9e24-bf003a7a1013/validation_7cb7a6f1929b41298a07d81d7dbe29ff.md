### Title
Missing Contract Existence Check on Custom Minter Call in `finTransfer` Silently Consumes Nonce Without Minting Tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`finTransfer` in `OmniBridge.sol` marks a destination nonce as used before calling the custom minter's `mint` function. There is no check that the custom minter address actually contains code. Per EVM specification, a call to a codeless address (self-destructed or never deployed) returns `success = true` with empty return data. If the custom minter contract is self-destructed after being registered, every subsequent `finTransfer` for that token silently succeeds without minting any tokens, permanently consuming the nonce and destroying the user's bridged funds with no recovery path.

---

### Finding Description

`finTransfer` processes inbound NEAR→EVM transfers. At line 287, the destination nonce is irrevocably consumed before any token transfer occurs: [1](#0-0) 

After signature verification, the function dispatches to one of several token-delivery branches. The custom minter branch at lines 331–336 calls an externally-supplied address with no contract existence guard: [2](#0-1) 

The `customMinters` mapping is populated by the admin via `addCustomToken`, which accepts any non-zero `customMinter` address: [3](#0-2) 

The `ICustomMinter` interface call is a high-level Solidity call that compiles to a low-level `call` opcode. The Solidity documentation explicitly warns: *"The low-level `call`, `delegatecall`, and `callcode` will return success if the calling account is non-existent, as part of the design of EVM."* If `customMinters[payload.tokenAddress]` has no code at call time, the `mint(...)` invocation returns `success = true` with zero return bytes. Solidity does not revert. No tokens are minted. The nonce is already consumed. The `FinTransfer` event is emitted as if the transfer succeeded. [4](#0-3) 

The other delivery branches do not share this flaw: the `safeTransfer` path uses OpenZeppelin `SafeERC20` which internally checks `address.code.length`; the `isBridgeToken` path calls contracts deployed by the bridge itself; the ERC-1155 path calls `safeTransferFrom` on a separately validated address.

---

### Impact Explanation

A bridge user who locks or burns tokens on NEAR and whose transfer is routed through a custom minter that has been self-destructed will:

1. Have their NEAR-side tokens permanently locked or burned (the NEAR hub considers the transfer finalized once the EVM nonce is consumed).
2. Receive zero tokens on EVM.
3. Have no replay path — `completedTransfers[payload.destinationNonce]` is `true`, so re-submitting the same signed payload reverts with `NonceAlreadyUsed`.

This is a **critical, irreversible loss of bridged funds** for every affected user. [1](#0-0) 

---

### Likelihood Explanation

Custom minter contracts are third-party contracts registered by the bridge admin. They may be:

- Upgradeable proxies whose implementation is later replaced with a self-destructing contract by the minter contract's own owner (distinct from the bridge admin).
- Contracts with an owner-callable `selfdestruct` that is triggered during a protocol migration or emergency shutdown of the minter protocol.

Once the minter self-destructs, **all future** `finTransfer` calls for that token silently fail. Any user who initiates a NEAR→EVM transfer for that token after the self-destruct — without any on-chain signal that the minter is gone — loses funds. The bridge emits a normal `FinTransfer` event, making the failure invisible to off-chain monitoring that only watches for reverts.

---

### Recommendation

Add an explicit contract existence check immediately before the custom minter call:

```solidity
address minter = customMinters[payload.tokenAddress];
require(minter.code.length > 0, "Custom minter has no code");
ICustomMinter(minter).mint(payload.tokenAddress, payload.recipient, payload.amount);
```

Alternatively, use a try/catch and revert on failure so the nonce is not consumed when the minter is absent. Additionally, emit an admin alert or add a `removedCustomMinter` guard so that a self-destructed minter can be detected and the token's delivery path can be updated before user funds are lost.

---

### Proof of Concept

1. Admin calls `addCustomToken("near-token.near", tokenEVM, minterContract, 18)`. `customMinters[tokenEVM] = minterContract`.
2. `minterContract` is self-destructed by its owner (e.g., protocol migration). `minterContract.code.length == 0`.
3. Alice locks 1000 NEAR-side tokens. The NEAR hub signs a `TransferMessagePayload` with `destinationNonce = N`, `tokenAddress = tokenEVM`, `amount = 1000`, `recipient = Alice_EVM`.
4. Relayer calls `finTransfer(sig, payload)` on `OmniBridge`.
5. Line 287: `completedTransfers[N] = true` — nonce consumed.
6. Line 311–313: ECDSA signature verifies successfully.
7. Line 331: `customMinters[tokenEVM] != address(0)` — true (mapping still holds the old address).
8. Line 332–336: `ICustomMinter(minterContract).mint(tokenEVM, Alice_EVM, 1000)` — EVM executes a `call` to a codeless address, returns `(true, "")`. No revert. No tokens minted.
9. Line 359: `FinTransfer` event emitted — bridge considers transfer complete.
10. Alice has lost 1000 tokens. Re-submission reverts with `NonceAlreadyUsed(N)`. [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L88-98)
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

```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
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

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
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

        finTransferExtension(payload);

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
