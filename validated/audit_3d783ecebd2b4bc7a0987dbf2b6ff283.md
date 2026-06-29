Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Double Minting on NEAR - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary

`initTransfer1155` increments `currentOriginNonce` before calling `safeTransferFrom` on an attacker-controlled ERC1155 token, but reads `currentOriginNonce` again — after the external call returns — when passing it to `initTransferExtension` and emitting `InitTransfer`. A malicious ERC1155 can reenter `initTransfer1155` during `safeTransferFrom`, causing both the inner and outer execution frames to emit `InitTransfer` events carrying the **same** `originNonce`. Because the NEAR-side `fin_transfer_callback` performs no deduplication on `origin_nonce`, both events can be independently finalized, minting bridged tokens twice for a single (or zero) EVM-side lock.

## Finding Description

In `initTransfer1155`, `currentOriginNonce` is incremented at line 448, but the incremented value is not captured into a local variable. The external call to the attacker-controlled ERC1155 token occurs at lines 458–464, and `currentOriginNonce` is read again — post-external-call — at lines 471 and 483: [1](#0-0) [2](#0-1) [3](#0-2) 

There is no reentrancy guard on `initTransfer1155`, and `tokenAddress` is fully attacker-controlled — no whitelist check is performed. [4](#0-3) 

**Reentrancy trace (single level, starting nonce = N):**

| Step | `currentOriginNonce` | Action |
|------|----------------------|--------|
| Outer enters | N → **N+1** | `currentOriginNonce += 1` |
| Outer hits `safeTransferFrom` | N+1 | Calls malicious ERC1155 |
| Malicious token reenters `initTransfer1155` | N+1 → **N+2** | Inner `currentOriginNonce += 1` |
| Inner hits `safeTransferFrom` | N+2 | Completes (malicious token skips `onERC1155Received`) |
| Inner emits `InitTransfer` | **N+2** | `currentOriginNonce` read = N+2 |
| Outer resumes | N+2 | — |
| Outer emits `InitTransfer` | **N+2** | `currentOriginNonce` read = N+2 ← **collision** |

Nonce N+1 is silently skipped; nonce N+2 appears in two distinct log entries in the same transaction. Both are valid Merkle-provable events.

**Why the `onERC1155Received` guard does not block this:** The bridge's receiver hook checks `operator != address(this)` and reverts if the operator is not the bridge itself. [5](#0-4) 

However, a malicious ERC1155 controls its own `safeTransferFrom` implementation entirely. It can reenter `initTransfer1155` without ever invoking `onERC1155Received` on the bridge. The guard is only triggered if the token chooses to call it; a malicious token will not.

**NEAR-side deduplication absent in `fin_transfer_callback`:** The callback verifies the emitter factory and token decimals, then assigns a fresh `destination_nonce` and proceeds unconditionally. No check against a previously seen `origin_nonce` is performed within this function: [6](#0-5) 

Each submitted proof generates an independent `destination_nonce` and proceeds to mint/unlock independently, meaning both proofs for nonce N+2 can be finalized.

The same structural flaw exists in `initTransfer` for ERC20 tokens (ERC-777 / hook-bearing tokens), where `currentOriginNonce` is also read post-external-call: [7](#0-6) 

This violates the documented invariant in `evm/CLAUDE.md`: [8](#0-7) 

## Impact Explanation

An attacker can mint an unbounded multiple of bridged tokens on NEAR without locking a corresponding amount of ERC1155 tokens on EVM. Each reentrant level doubles the number of valid `InitTransfer` proofs that can be submitted to NEAR. This constitutes **unauthorized minting** and **escrow mis-accounting**: the NEAR-side token supply grows beyond what is backed by EVM-side collateral, enabling the attacker to drain liquidity from any pool or bridge that accepts the minted token. This matches the critical impact class: *unauthorized minting, escrow mis-accounting, and balance manipulation across EVM and NEAR*.

## Likelihood Explanation

The attack requires only:
1. Deploying a malicious ERC1155 contract (permissionless, ~50 lines of Solidity).
2. Calling the permissionless `logMetadata1155` to register the token so NEAR accepts the event.
3. Calling `initTransfer1155` — a public, unpermissioned function — with the malicious token address.

No admin access, no leaked keys, no front-running, and no collusion are required. The entry path is fully reachable by any unprivileged EVM user. The attack is repeatable across multiple transactions.

## Recommendation

1. **Capture the nonce in a local variable before the external call** and use that local variable in `initTransferExtension` and `emit`:
   ```solidity
   currentOriginNonce += 1;
   uint64 nonce = currentOriginNonce; // capture before external call
   // ... external call ...
   initTransferExtension(..., nonce, ...);
   emit BridgeTypes.InitTransfer(..., nonce, ...);
   ```
2. **Add a reentrancy guard** (`ReentrancyGuardUpgradeable` from OpenZeppelin) to `initTransfer1155` and `initTransfer`.
3. **Add `origin_nonce` deduplication on the NEAR side** in `fin_transfer_callback` using a set keyed on `{origin_chain, origin_nonce}` to reject duplicate proofs.

## Proof of Concept

Deploy a malicious ERC1155 contract whose `safeTransferFrom` reenters `initTransfer1155` once before returning:

```solidity
contract MaliciousERC1155 is ERC1155 {
    OmniBridge bridge;
    bool reentered;

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory) public override {
        if (!reentered) {
            reentered = true;
            // Reenter initTransfer1155 — inner call increments nonce to N+2 and emits InitTransfer(N+2)
            bridge.initTransfer1155{value: msg.value}(address(this), id, amount, fee, nativeFee, recipient, message);
        }
        // Do not call onERC1155Received — skip the bridge's guard entirely
        reentered = false;
    }
}
```

**Steps:**
1. Deploy `MaliciousERC1155` pointing to the bridge.
2. Call `bridge.logMetadata1155(maliciousToken, tokenId)` to register the token on NEAR.
3. Call `bridge.initTransfer1155(maliciousToken, tokenId, amount, fee, nativeFee, recipient, message)`.
4. Observe two `InitTransfer` events in the transaction receipt, both with `originNonce = N+2`.
5. Submit both Merkle proofs to the NEAR `fin_transfer` endpoint.
6. Observe two independent minting operations on NEAR for a single (or zero) EVM-side lock.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-436)
```text
        initTransferExtension(
            msg.sender,
            tokenAddress,
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
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-447)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-448)
```text
        currentOriginNonce += 1;
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L468-489)
```text
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
