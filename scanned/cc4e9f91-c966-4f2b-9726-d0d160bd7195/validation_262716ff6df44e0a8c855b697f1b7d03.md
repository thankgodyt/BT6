### Title
Re-entrancy in `initTransfer1155` via Malicious ERC1155 Token Enables Unauthorized Minting on NEAR — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155` makes an external call to a fully attacker-controlled ERC1155 token contract with no re-entrancy guard. A malicious token's `safeTransferFrom` can re-enter `initTransfer1155` an arbitrary number of times. Each re-entrant frame increments `currentOriginNonce` and eventually emits a distinct `InitTransfer` event. The NEAR bridge processes every such event as an independent, valid transfer and mints bridged tokens for each one, while the attacker deposits zero (or one) ERC1155 tokens on Ethereum.

---

### Finding Description

`initTransfer1155` (lines 439–490) follows this sequence:

1. `currentOriginNonce += 1` — nonce incremented.
2. `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` — **external call to attacker-controlled contract**.
3. `initTransferExtension(...)` — optional Wormhole publish.
4. `emit BridgeTypes.InitTransfer(...)` — event emitted. [1](#0-0) 

There is no `nonReentrant` modifier and no `ReentrancyGuardUpgradeable` import anywhere in the contract. [2](#0-1) 

The `tokenAddress` parameter is **fully attacker-controlled** — there is no whitelist check before the external call. A malicious ERC1155 token's `safeTransferFrom` can call back into `initTransfer1155` before returning:

```
initTransfer1155(malicious, id, 1, …)          ← outer, nonce = N
  └─ malicious.safeTransferFrom(…)
       └─ initTransfer1155(malicious, id, 1, …) ← inner, nonce = N+1
            └─ malicious.safeTransferFrom(…)
                 └─ … (repeat K times)
            emit InitTransfer(nonce=N+K)
       emit InitTransfer(nonce=N+1)
  emit InitTransfer(nonce=N)
```

Each frame emits a unique `InitTransfer` event. The NEAR bridge's `fin_transfer` deduplicates by `(origin_chain, origin_nonce)`: [3](#0-2) 

Because every re-entrant frame produces a **different** nonce, every event passes the NEAR-side deduplication check and triggers an independent mint.

The same structural flaw exists in the ERC20 `initTransfer` "else" path, where `IERC20(tokenAddress).safeTransferFrom` is called on an attacker-supplied token with no guard: [4](#0-3) 

The `logMetadata` and `logMetadata1155` entry points are **permissionless**, so the attacker can register any token address and trigger NEAR-side bridge-token deployment before executing the attack: [5](#0-4) [6](#0-5) 

The CLAUDE.md security invariant "State before external calls" is only partially satisfied: the nonce is incremented before the external call, but the `InitTransfer` event — which is the sole proof the NEAR side relies on — is emitted **after** the external call, inside each re-entrant frame. [7](#0-6) 

---

### Impact Explanation

An attacker can emit K+1 `InitTransfer` events while depositing zero ERC1155 (or ERC20) tokens. The NEAR bridge mints K+1 times the stated `amount` to the attacker's NEAR address. This constitutes unauthorized minting and direct theft of bridged-token supply, draining the bridge's token reserves on NEAR. Impact is **Critical**: unauthorized minting / escrow mis-accounting of bridged funds.

---

### Likelihood Explanation

The attack is fully permissionless and requires no privileged access:
- Any EOA can deploy a malicious ERC1155 token.
- `logMetadata1155` is callable by anyone.
- `initTransfer1155` is callable by anyone while not paused.
- No admin compromise, oracle manipulation, or front-running is required.

Likelihood is **High**.

---

### Recommendation

1. Import and inherit `ReentrancyGuardUpgradeable` from OpenZeppelin and apply `nonReentrant` to `initTransfer`, `initTransfer1155`, and `finTransfer`.
2. As defense-in-depth, emit `InitTransfer` **before** the external token call (full CEI), or validate that `tokenAddress` is a registered bridge token before calling into it.

---

### Proof of Concept

```solidity
// MaliciousERC1155.sol
contract MaliciousERC1155 {
    OmniBridge bridge;
    uint256 depth;

    function safeTransferFrom(address, address, uint256 id, uint256 amount, bytes calldata) external {
        if (depth < 5) {
            depth++;
            // Re-enter initTransfer1155 — each call increments currentOriginNonce
            bridge.initTransfer1155(address(this), id, uint128(amount), 0, 0, "attacker.near", "");
            depth--;
        }
        // Never actually transfers tokens
    }
    // ... minimal ERC1155 stubs
}
```

**Steps:**
1. Deploy `MaliciousERC1155` pointing at the bridge.
2. Call `bridge.logMetadata1155(address(malicious), tokenId)` — permissionless registration.
3. Wait for NEAR to deploy a bridge token for `deterministicToken`.
4. Call `bridge.initTransfer1155(address(malicious), tokenId, 1, 0, 0, "attacker.near", "")`.
5. Re-entrancy fires 5 levels deep → 6 `InitTransfer` events emitted with nonces N … N+5.
6. NEAR processes all 6 events, minting 6 tokens to `attacker.near`.
7. Attacker deposited **0** ERC1155 tokens on Ethereum. [8](#0-7) [9](#0-8)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L1-20)
```text
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ICustomMinter} from "../../common/ICustomMinter.sol";
import {IBridgeToken} from "../../common/IBridgeToken.sol";

import "./BridgeToken.sol";
import "./SelectivePausableUpgradable.sol";
import "../../common/Borsh.sol";
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-412)
```text
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
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

**File:** near/omni-bridge/src/lib.rs (L1985-1986)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
        let token = self.get_token_id(&transfer_message.token);
```

**File:** evm/CLAUDE.md (L34-36)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
