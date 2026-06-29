Based on my code investigation, the claim is substantiated by the actual code. Key findings:

1. `normalize_amount` at L2784-2787 uses floor division with no zero-guard. [1](#0-0) 

2. The zero-amount `require!` guard exists only in `sign_transfer` at L482-485, **after** the transfer is already committed to storage. [2](#0-1) 

3. `init_transfer_internal` at L1829-1865 has no pre-normalization check; it commits the transfer, burns/locks tokens, and returns `U128(0)` (full consumption signal to the NEP-141 contract). [3](#0-2) 

4. The code comment at L2781-2782 explicitly acknowledges: *"When fee = 0, dust stays locked/burned."* — but this only addresses remainder dust, not the case where the **entire** amount normalizes to zero, leaving the transfer permanently uncompletable. [4](#0-3) 

---

Audit Report

## Title
Zero-Normalized Amount Causes Permanent Transfer Lock — (File: near/omni-bridge/src/lib.rs)

## Summary
When a user initiates an outbound NEAR→EVM transfer with an amount smaller than `10^(origin_decimals − decimals)`, `normalize_amount` returns `0` via floor division. The transfer is committed to `pending_transfers` and tokens are burned/locked inside `init_transfer_internal` before any normalization check occurs. Every subsequent `sign_transfer` call permanently reverts with `InvalidAmountToTransfer`, and no cancellation or refund path exists, freezing the funds forever.

## Finding Description
`normalize_amount` performs floor division: `amount / 10^(origin_decimals - decimals)`. For a token with `origin_decimals=24` and `decimals=18`, any amount below `1_000_000` yocto-units yields `0`.

The only zero-amount guard is inside `sign_transfer` at L482–485, which executes **after** `init_transfer_internal` has already:
1. Called `add_transfer_message` to commit the entry to `pending_transfers` (L1835).
2. Called `burn_tokens_if_needed` / `lock_tokens_if_needed` to consume the tokens (L1851–1857).
3. Returned `U128(0)` to the NEP-141 contract, signaling full consumption and preventing any automatic refund (L1864).

The code comment at L2781–2782 acknowledges dust locking when `fee=0`, but only addresses remainder dust — not the distinct case where the entire amount normalizes to zero, making the transfer permanently uncompletable. The only removal paths for `pending_transfers` entries (`claim_fee_callback`, `fin_transfer_callback`) require proof of destination-chain finalization that will never exist for this transfer.

## Impact Explanation
This constitutes **permanent freezing of bridged funds** — a Critical impact under the allowed scope. The NEP-141 tokens (or wNEAR) are irrecoverably consumed: the NEP-141 contract receives `0` as the refund signal, `sign_transfer` always reverts for the affected `transfer_id`, and no user-callable cancel or refund function exists. The funds cannot be recovered by the user or the protocol.

## Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_transfer_call` on a registered NEAR token with a sub-threshold amount. For the common 24→18 decimal pairing, amounts below `1_000_000` yocto-units (less than 1 µNEAR) trigger the bug. A user sending dust, making a rounding error, or using a UI that does not validate post-normalization amounts can silently lose funds. The `ft_on_transfer` call succeeds and returns no error to the sender, making the loss non-obvious.

## Recommendation
Add a normalization check at the top of `init_transfer_internal` (or inside `ft_on_transfer`) before the transfer is committed. If the normalized amount is zero, return the full amount to the caller as a refund:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but places it at the correct, earlier point in the lifecycle — before tokens are burned/locked and before `U128(0)` is returned to the NEP-141 contract.

## Proof of Concept
1. Register a token with `origin_decimals=24`, `decimals=18`.
2. Call `ft_transfer_call` sending `500_000` yocto-units to the bridge with a valid `InitTransferMsg` (fee=0).
3. `ft_on_transfer` → `init_transfer_internal` commits the transfer, burns 500,000 units, returns `U128(0)`.
4. Call `sign_transfer` for the resulting `transfer_id`.
5. `normalize_amount(500_000, {origin:24, decimals:18})` = `500_000 / 1_000_000` = `0`.
6. `require!(amount_to_transfer > 0, …)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Repeat step 4 indefinitely — always reverts. The 500,000 yocto-units are permanently locked with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
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

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
