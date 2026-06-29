Audit Report

## Title
`is_refund_required` Ignores Promise Failure for `ft_transfer` and Panicked `ft_transfer_call`, Permanently Finalizing Transfer Without Token Delivery — (`near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` unconditionally returns `false` when `is_ft_transfer_call` is `false` (plain `ft_transfer` path), and also returns `false` when `is_ft_transfer_call` is `true` but the promise result is `Err`. In both cases, a failed token delivery causes `fin_transfer_send_tokens_callback` to take the success branch: it pays the relayer fee and emits `FinTransferEvent`, while the transfer ID remains permanently in `finalised_transfers` and the locked-token counter is never restored. The recipient receives nothing and no retry is possible.

## Finding Description

The `is_refund_required` function at L1784–1804 has two silent failure paths:

**Path A — `ft_transfer` (empty `msg`):** `is_ft_transfer_call` is `false`, so the function returns `false` without ever inspecting the promise result. If the underlying `ft_transfer` call panics (e.g., recipient blacklisted, token paused, insufficient storage), the promise result is `Err`, but `is_refund_required` still returns `false`.

**Path B — `ft_transfer_call` protocol panic:** If the token contract panics before `ft_resolve_transfer` can return a value, the promise result is `Err`. The `Err(_) => false` arm at L1798 also returns `false`.

In both cases, `fin_transfer_send_tokens_callback` (L1702) takes the `else` branch (L1719–1746): it pays the fee to the relayer and emits `FinTransferEvent` as if the transfer succeeded. The revert path — `revert_lock_actions`, `remove_fin_transfer`, `FailedFinTransferEvent` — is never reached.

The state damage is:
- `add_fin_transfer` (L1875) has already inserted the transfer ID into `finalised_transfers` — replay protection blocks any retry.
- `unlock_tokens_if_needed` (L1881–1885) has already decremented the locked-token counter for the origin chain — this is never restored.
- For native tokens: tokens remain stranded inside the bridge contract.
- For deployed tokens: the mint never happened; source-chain tokens are permanently locked.

The same `is_refund_required` is also called from `resolve_utxo_fin_transfer` (L1025) and `resolve_fast_transfer` (L906), so both flows share the same flaw.

## Impact Explanation

This constitutes **permanent freezing of bridged funds**. After a failed `ft_transfer`:
- The transfer ID is consumed — no replay, no retry.
- The locked-token counter is permanently decremented — accounting is corrupted.
- For native tokens: funds are stranded in the bridge with no withdrawal path.
- For deployed tokens: source-chain tokens are permanently locked with no corresponding mint on NEAR.
- The relayer is paid a fee for a transfer that never completed.

This matches the allowed critical impact: *permanent freezing of bridged funds* and *escrow mis-accounting / balance manipulation*.

## Likelihood Explanation

`ft_transfer` failure is a realistic, non-hypothetical production condition:
- NEP-141 tokens with recipient blacklists or compliance pauses (common for regulated tokens).
- A token contract administratively paused between the storage-deposit check and the actual transfer.
- For deployed `omni-token` via `mint`: if the token contract is paused or the bridge's mint authority is revoked.

The bridge explicitly supports arbitrary NEP-141 tokens. Any relayer (unprivileged external actor) can trigger `fin_transfer` with a token that has transfer restrictions, causing the bug. No special privileges or victim mistakes are required — the failure is caused entirely by the token contract's normal behavior.

## Recommendation

`is_refund_required` must inspect the promise result regardless of `is_ft_transfer_call`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Err(_) => true, // promise failed → always revert
        Ok(value) if is_ft_transfer_call => {
            near_sdk::serde_json::from_slice::<U128>(&value)
                .map_or(false, |a| a.0 == 0)
        }
        Ok(_) => false, // ft_transfer succeeded
    }
}
```

This ensures any protocol-level failure of `ft_transfer` or `ft_transfer_call` triggers `revert_lock_actions` and `remove_fin_transfer`, restoring the locked-token counter and allowing the transfer to be retried.

## Proof of Concept

1. Deploy a NEP-141 token contract with a recipient blacklist. Register it with the bridge.
2. Blacklist a target recipient address.
3. Initiate a cross-chain transfer from Ethereum for that recipient with an empty `msg` (plain `ft_transfer` path).
4. Relayer calls `fin_transfer` on NEAR. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer` marks the transfer ID as used (L1875).
   - `unlock_tokens_if_needed` decrements the locked counter (L1881–1885).
   - `send_tokens` calls `ft_transfer(recipient, amount, None)` on the token contract.
5. Token contract panics — recipient is blacklisted — promise result is `Err`.
6. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false` unconditionally (L1800–1802).
8. The `else` branch fires (L1719): fee is paid to the relayer, `FinTransferEvent` is emitted.
9. Transfer ID is permanently in `finalised_transfers`; `revert_lock_actions` is never called.
10. Recipient has received nothing. Ethereum tokens are permanently locked. No retry is possible.

A local integration test can reproduce this by mocking a token contract whose `ft_transfer` panics and asserting that after the callback: (a) `finalised_transfers` contains the transfer ID, (b) the locked-token counter has not been restored, and (c) the recipient balance is zero.