Audit Report

## Title
`fin_transfer_send_tokens_callback` Silently Ignores `ft_transfer` Failure, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` unconditionally returns `false` for any non-`ft_transfer_call` path, meaning a panicking plain `ft_transfer` is treated as a success. Because `add_fin_transfer` and `unlock_tokens_if_needed` commit state before the token send, a failed delivery leaves the transfer ID permanently in `finalised_transfers`, `locked_tokens` decremented, and the recipient with zero tokens — with no recovery path.

## Finding Description

**Root cause — `is_refund_required` never inspects the promise result for plain `ft_transfer`:**

```rust
// near/omni-bridge/src/lib.rs L1784-1803
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) { … }
    } else {
        // Not ft_transfer_call: don't refund
        false   // ← always false, promise result never read
    }
}
```

**`send_tokens` dispatches a plain `ft_transfer` when `msg` is empty (non-deployed token path):**

```rust
// L2102-2106
} else if msg.is_empty() {
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)
```

**The callback is scheduled with `is_ft_transfer_call = !msg.is_empty()` (i.e., `false` for the empty-msg path):**

```rust
// L1967-1977
.then(
    Self::ext(env::current_account_id())
        …
        .fin_transfer_send_tokens_callback(
            transfer_message,
            &fee_recipient,
            !msg.is_empty(),   // ← false when msg is empty
            …
        ),
)
```

**State is committed in the same receipt, before the token send:**

```rust
// L1875, L1881-1885
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
…
let lock_actions = vec![self.unlock_tokens_if_needed(
    transfer_message.get_origin_chain(),
    &token,
    transfer_message.amount.0,
)];
```

Both `add_fin_transfer` (inserts into `finalised_transfers`) and `unlock_tokens_if_needed` (decrements `locked_tokens`) execute and commit in the receipt that calls `process_fin_transfer_to_near`. They cannot be rolled back by a failure in the subsequent `ft_transfer` receipt.

**Callback takes the success branch on failure:**

```rust
// L1702, L1719-1745
if Self::is_refund_required(is_ft_transfer_call) {   // always false here
    …FailedFinTransferEvent…
} else {
    // pays relayer fee, emits FinTransferEvent — even if ft_transfer panicked
}
```

The same structural defect is present in `resolve_fast_transfer` (L906) and `resolve_utxo_fin_transfer` (L1024-1025), which both delegate to the same `is_refund_required` helper with the same blind spot.

## Impact Explanation

This matches the critical allowed impact: **permanent freezing of bridged funds**. Concretely:

1. The origin-chain proof is consumed; `finalised_transfers` blocks any re-submission (replay protection).
2. `locked_tokens` is decremented, breaking internal accounting.
3. The recipient receives zero tokens; they remain stranded in the bridge contract.
4. The relayer collects its fee for a delivery that never occurred.

There is no admin recovery path: the transfer ID is permanently recorded and the proof cannot be resubmitted.

## Likelihood Explanation

USDC and USDC.e are among the most commonly bridged assets and use an actively maintained blacklist. Any user whose NEAR address is blacklisted after initiating a bridge transfer — or who specifies a blacklisted recipient — triggers this path. No privileged access is required; the exploit is reachable via a standard public `fin_transfer` call with an empty `msg` for any non-deployed (locked) token whose contract can reject `ft_transfer`. The code path is exercised on every standard inbound `fin_transfer` for such tokens.

## Recommendation

In `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer`, check the promise result unconditionally — not only when `is_ft_transfer_call` is `true`. Extend `is_refund_required` (or add a separate check) to call `env::promise_result_checked(0, …)` for the plain `ft_transfer` case and treat a failed promise (`Err(_)`) as requiring a refund. On failure: revert lock actions, remove the finalized-transfer record, and emit `FailedFinTransferEvent` instead of `FinTransferEvent`.

## Proof of Concept

1. Deploy a NEAR FT contract that rejects `ft_transfer` to a specific address (simulating a USDC blacklist).
2. Register that token with the bridge as a non-deployed (locked) token.
3. Lock tokens on the EVM side; submit a valid `fin_transfer` proof to the NEAR bridge targeting the blacklisted address with an empty `msg`.
4. Observe that `process_fin_transfer_to_near` → `add_fin_transfer` commits the transfer ID to `finalised_transfers` and `unlock_tokens_if_needed` decrements `locked_tokens` in the same receipt.
5. The `ft_transfer` to the blacklisted address panics; `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
6. `is_refund_required(false)` returns `false`; the callback emits `FinTransferEvent` and pays the relayer fee.
7. Confirm: recipient balance is zero, `finalised_transfers` contains the transfer ID (preventing retry), `locked_tokens` is decremented, and tokens remain stranded in the bridge contract permanently.