Audit Report

## Title
Re-entrancy via Malicious ERC1155 Token Causes `currentOriginNonce` Collision, Enabling Unauthorized Minting on NEAR - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary

`initTransfer1155` increments `currentOriginNonce` before an external `safeTransferFrom` call but emits `InitTransfer` using the **live storage value** of `currentOriginNonce` after the external call returns. A malicious ERC1155 token can re-enter `initTransfer1155` from within its `safeTransferFrom` body, incrementing `currentOriginNonce` a second time, causing both the re-entrant and original invocations to emit `InitTransfer` with the **same** `origin_nonce`. NEAR processes the first (re-entrant, no tokens locked) event and mints tokens to the attacker; the second event is rejected as a duplicate nonce.

## Finding Description

In `initTransfer1155`: [1](#0-0) 

`currentOriginNonce` is incremented to N+1 before the external call. [2](#0-1) 

`IERC1155(tokenAddress).safeTransferFrom(...)` is called — this is an external call to an arbitrary, potentially malicious contract. [3](#0-2) 

The event is emitted using `currentOriginNonce` — the **live storage value** — not a locally captured snapshot. If re-entrancy has occurred during the external call, this value has been modified.

The same pattern exists in `initTransfer`: [4](#0-3) [5](#0-4) 

Neither function has a `nonReentrant` modifier. The `onERC1155Received` hook: [6](#0-5) 

...checks `operator != address(this)` and is declared `view`. This only prevents direct ERC1155 sends to the bridge. It does **not** prevent re-entrancy: a malicious token's `safeTransferFrom` can call back into `initTransfer1155` from within its own function body, entirely before (or without) invoking `onERC1155Received` on the bridge. The bridge has no mechanism to verify that `onERC1155Received` was actually called.

**Attack trace:**

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` re-enters `initTransfer1155` on first invocation and returns immediately on second.
2. Attacker calls `logMetadata1155` (permissionless per `evm/SECURITY.md`) to register the token; NEAR processes the `LogMetadata` event.
3. Attacker calls `initTransfer1155(maliciousToken, ...)`:
   - `currentOriginNonce` → N+1
   - Bridge calls `maliciousToken.safeTransferFrom(...)`
   - Inside malicious token: re-enters `initTransfer1155`
     - `currentOriginNonce` → N+2
     - Bridge calls `maliciousToken.safeTransferFrom(...)` again; malicious token returns immediately (no tokens transferred, `onERC1155Received` not called)
     - `initTransferExtension(...)` called with live `currentOriginNonce = N+2`
     - `emit InitTransfer(..., N+2, ...)` ← **re-entrant event, no tokens locked**
   - Outer `safeTransferFrom` returns (also without transferring tokens)
   - `initTransferExtension(...)` called with live `currentOriginNonce = N+2`
   - `emit InitTransfer(..., N+2, ...)` ← **duplicate nonce, tokens also not locked**
4. Transaction log contains two `InitTransfer` events with `origin_nonce = N+2`; nonce N+1 is permanently skipped.
5. Attacker (acting as relayer, or racing the legitimate relayer) submits the first (re-entrant) event proof to NEAR.
6. NEAR's `fin_transfer_callback` processes it, mints/releases tokens to `attacker.near`.
7. Second event with same nonce is rejected as duplicate `TransferId`. [7](#0-6) 

The `fin_transfer_callback` constructs a `TransferMessage` keyed by `origin_nonce`. The first submission with nonce N+2 succeeds; the second is rejected. No tokens were ever locked on EVM.

This directly violates the stated invariant in `evm/CLAUDE.md`: [8](#0-7) 

The nonce is incremented before the external call (partially correct), but the event emission reads the live storage value after the external call — the invariant is broken because re-entrancy can modify `currentOriginNonce` between increment and emit.

## Impact Explanation

This is **unauthorized minting of bridged funds** — a critical bridge invariant violation. The NEAR side treats any emitted `InitTransfer` event as proof that tokens are held on EVM. Because the re-entrant event carries no actual EVM collateral, the attacker receives bridged assets on NEAR without locking the corresponding ERC1155 tokens on EVM. This matches the allowed critical impact: *"unauthorized minting... that changes user or protocol balances"* and *"Event–transfer atomicity"* violation where `InitTransfer` is emitted without tokens being burned/locked.

## Likelihood Explanation

- `logMetadata1155` is explicitly permissionless — any address can register any ERC1155 token.
- No `nonReentrant` guard exists on `initTransfer` or `initTransfer1155`.
- The `onERC1155Received` operator check does not block re-entrancy through the token's own `safeTransferFrom`.
- The attacker needs only to deploy a malicious ERC1155 contract and call two public functions (`logMetadata1155`, `initTransfer1155`).
- The attacker can act as their own relayer to ensure the re-entrant event is submitted first to NEAR.
- The attack is repeatable and requires no privileged access.

## Recommendation

1. **Capture the nonce into a local variable before any external call** and use that local variable in `initTransferExtension` and `emit`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
    ...
    initTransferExtension(msg.sender, deterministicToken, nonce, ...);
    emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
}
```

Apply the same fix to `initTransfer` (capture nonce before the ERC20 `safeTransferFrom` / `burn` calls).

2. **Add `ReentrancyGuard` (`nonReentrant` modifier)** to both `initTransfer` and `initTransfer1155` as defense-in-depth, consistent with the security invariants in `evm/CLAUDE.md`.

## Proof of Concept

Deploy `MaliciousERC1155` with a `safeTransferFrom` that re-enters `initTransfer1155` on first call and returns immediately on second. Call `logMetadata1155(maliciousToken, ...)` to register it. Call `initTransfer1155(maliciousToken, tokenId, amount, 0, 0, "attacker.near", "")` with `msg.value = 0`.

Expected result: transaction emits two `InitTransfer` events both with `origin_nonce = N+2`. Nonce N+1 is skipped. Submit the first event proof to NEAR's `fin_transfer` — NEAR mints tokens to `attacker.near`. Submit the second proof — NEAR rejects it as a duplicate `TransferId`. The attacker retains their ERC1155 tokens on EVM while receiving bridged value on NEAR.

A local Hardhat/Foundry test can confirm the duplicate-nonce emission without a live NEAR environment; the NEAR-side rejection of the second proof follows from the `TransferId` uniqueness check in `fin_transfer_callback`.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L381-381)
```text
        currentOriginNonce += 1;
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L480-489)
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

**File:** evm/CLAUDE.md (L33-36)
```markdown
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
