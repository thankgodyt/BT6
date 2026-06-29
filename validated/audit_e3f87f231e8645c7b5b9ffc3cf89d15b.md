All code references check out. Let me verify the complete picture:

**`init_transfer` validation** — only `fee.fee < amount`, no normalization check. [1](#0-0) 

**`sign_transfer` normalization check** — panics when `amount_to_transfer == 0`. [2](#0-1) 

**`normalize_amount`** — confirmed floor division. [3](#0-2) 

**`init_transfer_internal`** — on success returns `U128(0)`, keeping tokens in the bridge; only returns `transfer_message.amount` (refund) on storage failure or non-NEAR token. [4](#0-3) 

**`sign_transfer_callback`** — only removes the transfer if signing succeeds AND fee is zero; never reached when `sign_transfer` panics before calling MPC. [5](#0-4) 

**`claim_fee_callback`** — removes transfer only after verifying a `FinTransferMessage` proof from the destination chain, which can never exist for an unsigned transfer. [6](#0-5) 

No `cancel_transfer` or emergency-withdraw function exists anywhere in the contract.


The `normalize_amount` doc comment acknowledges dust locking when `fee = 0`, but this is scoped to sub-unit remainders, not the case where the entire `amount_without_fee` normalizes to zero. [7](#0-6) 

All six required validation checks pass. The exploit is reachable by any unprivileged user via `ft_transfer_call`, the code behaves exactly as claimed, and the impact is concrete permanent freezing of bridged funds.

---

Audit Report

## Title
Missing Pre-Validation of Normalized Transfer Amount Permanently Freezes Bridged Funds — (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts and stores a `TransferMessage` in `pending_transfers` — locking the user's tokens in the bridge — without verifying that `normalize_amount(amount - fee, decimals) > 0`. When the raw amount is below the decimal-gap threshold (e.g., `< 10^18` yoctoNEAR for a NEAR→EVM 24→6 decimal pair), `sign_transfer` unconditionally panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` on every invocation. No cancel, refund, or emergency-withdraw path exists, so the tokens are permanently frozen.

## Finding Description

**Root cause — `init_transfer` (L554–557):**
The only pre-condition enforced is `fee.fee < amount`. There is no check that `normalize_amount(amount - fee, decimals) > 0`. `init_transfer_internal` then stores the `TransferMessage` in `pending_transfers` and returns `U128(0)` to the NEP-141 callback, causing the token contract to keep the tokens with the bridge.

**Blocking check — `sign_transfer` (L475–485):**
`sign_transfer` is the sole function that can advance a NEAR-originated pending transfer. It computes:
```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```
`normalize_amount` performs floor division: `amount / 10^(origin_decimals - decimals)`. For a 24→6 decimal pair the divisor is `10^18`; any `amount_without_fee < 10^18` produces `amount_to_transfer = 0`, causing a panic on every call.

**No recovery path:**
- `sign_transfer_callback` removes the transfer only if MPC signing succeeds and fee is zero — never reached because `sign_transfer` panics before calling MPC.
- `claim_fee_callback` requires a `FinTransferMessage` proof of finalization on the destination chain — impossible since the transfer was never signed.
- No `cancel_transfer` or emergency-withdraw function exists.

## Impact Explanation
Permanent freezing of bridged funds — a Critical allowed impact. The user's tokens are irrecoverably locked in the bridge contract. The threshold below which a transfer becomes unrecoverable is `10^(origin_decimals − decimals)` raw units: for NEAR→EVM (24→6) this is `10^18` yoctoNEAR (0.000001 NEAR); for NEAR→Solana (24→9) it is `10^15` yoctoNEAR (0.001 NEAR). There is no admin escape hatch.

## Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_transfer_call` on a NEAR token contract with a sub-threshold amount and a valid destination recipient. No special role, key, or privileged access is required. The `init_transfer` validation does not prevent it. The condition is easy to satisfy accidentally (small test transfers) or deliberately.

## Recommendation
Add a normalization pre-check inside `init_transfer` (or `init_transfer_internal`) before tokens are locked, mirroring the check already present in `sign_transfer`:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```
This rejects the transfer before `init_transfer_internal` stores it and before the NEP-141 callback commits the tokens to the bridge.

## Proof of Concept
1. Deploy the bridge with a NEAR token mapped to an EVM token with `origin_decimals = 24`, `decimals = 6`.
2. Call `ft_transfer_call` with `amount = 10^17` yoctoNEAR (0.0000001 NEAR), `fee = 0`, valid EVM recipient.
3. Observe `InitTransferEvent` emitted — tokens are now held by the bridge; `pending_transfers` contains the entry.
4. Call `sign_transfer` for the resulting `transfer_id` from any trusted relayer.
5. Observe panic: `ERR_INVALID_AMOUNT_TO_TRANSFER`.
6. Repeat step 4 indefinitely — always panics.
7. Attempt `claim_fee` — fails because no finalization proof exists on the destination chain.
8. Tokens are permanently locked with no recovery path.

A unit test can be written directly against `sign_transfer_callback` and `init_transfer_internal` using the existing test harness in `near/omni-bridge/src/tests/lib_test.rs`, setting `origin_decimals = 24`, `decimals = 6`, and `amount = 10^17` to confirm the panic and the absence of any removal from `pending_transfers`.

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1075-1094)
```rust
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
