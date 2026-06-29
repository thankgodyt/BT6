Audit Report

## Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Tokens When Transfer Fails at Runtime — (File: `near/omni-bridge/src/lib.rs`)

## Summary
In `process_fin_transfer_to_near`, the transfer ID is committed to `finalised_transfers` via `add_fin_transfer` before any token movement occurs. When `send_tokens` issues a plain `ft_transfer` (non-deployed token, empty `msg`), the callback `fin_transfer_send_tokens_callback` calls `is_refund_required(false)`, which unconditionally returns `false` without reading the promise result. A failed `ft_transfer` is therefore treated identically to a successful one, the transfer ID remains permanently finalized, and the locked tokens are frozen inside the bridge with no recovery path.

## Finding Description

**Step 1 — Transfer ID committed before token movement.**

`process_fin_transfer_to_near` calls `add_fin_transfer` as its first action:

```rust
// near/omni-bridge/src/lib.rs L1875
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

This inserts the transfer ID into the replay-protection set. The state change is committed in the same receipt, before any cross-contract call.

**Step 2 — `send_tokens` uses `ft_transfer` for locked tokens with empty `msg`.**

```rust
// near/omni-bridge/src/lib.rs L2102-2106
} else if msg.is_empty() {
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)
```

For any non-deployed, non-wNEAR token with an empty `msg`, a plain `ft_transfer` is used. If the token contract panics (blacklisted recipient, paused contract, transfer-fee shortfall), the promise result is `Failed`.

**Step 3 — Callback is chained with `is_ft_transfer_call = false`.**

```rust
// near/omni-bridge/src/lib.rs L1967-1977
.then(
    Self::ext(env::current_account_id())
        .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
        .fin_transfer_send_tokens_callback(
            transfer_message,
            &fee_recipient,
            !msg.is_empty(),   // false when ft_transfer was used
            predecessor_account_id,
            lock_actions,
        ),
)
```

**Step 4 — `is_refund_required` never reads the promise result for the `ft_transfer` path.**

```rust
// near/omni-bridge/src/lib.rs L1784-1804
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) { ... }
    } else {
        // Not ft_transfer_call: don't refund
        false   // ← promise result is never inspected
    }
}
```

When `is_ft_transfer_call = false`, the function returns `false` immediately. A failed `ft_transfer` is indistinguishable from a successful one.

**Step 5 — "Success" branch fires: fee paid, event emitted, transfer permanently finalized.**

```rust
// near/omni-bridge/src/lib.rs L1719-1746
} else {
    if transfer_message.fee.fee.0 > 0 {
        ext_token::ext(token)...ft_transfer(fee_recipient...).detach();
    }
    env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
}
```

The bridge emits `FinTransferEvent` and pays the relayer fee as if the transfer succeeded, while the user's tokens remain locked with no recovery path.

## Impact Explanation

The transfer ID is permanently in `finalised_transfers`; any re-submission of the same proof is rejected as a replay. There is no admin function to remove a finalized transfer or re-execute the token send. The locked tokens remain in the bridge contract indefinitely. This constitutes **permanent freezing of bridged funds**, which is an explicitly listed Critical impact in the allowed scope.

## Likelihood Explanation

The `ft_transfer` path is reached for any non-deployed, non-wNEAR token (e.g., USDC, USDT) bridged to NEAR with an empty `msg`. Realistic failure triggers include:

1. **USDC/USDT blacklist**: Centre/Tether can blacklist NEAR addresses. Any user whose NEAR address is blacklisted after initiating a bridge transfer will have their funds permanently frozen upon finalization. No privileged access to the bridge is required.
2. **Token pause**: If the NEAR-side token contract is paused by its admin at the moment `fin_transfer` is processed, `ft_transfer` panics and the funds are frozen.
3. **Transfer-fee tokens**: A token that deducts a fee on transfer may leave the bridge with insufficient balance, causing `ft_transfer` to panic.

No privileged bridge access is required. The relayer simply submits a valid proof; the failure is caused by the token contract's runtime behavior.

## Recommendation

In `is_refund_required`, check the promise result for the `ft_transfer` path as well:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => serde_json::from_slice::<U128>(&value)
                .map(|a| a.0 == 0)
                .unwrap_or(false),
            Err(_) => true,
        }
    } else {
        // ft_transfer: refund if the promise failed
        env::promise_result_checked(0, 0).is_err()
    }
}
```

When `ft_transfer` fails, the refund path should execute: revert lock actions, call `remove_fin_transfer`, and emit `FailedFinTransferEvent` so the relayer can retry after the blocking condition is resolved.

## Proof of Concept

1. User bridges 1000 USDC (non-deployed, locked token) from Ethereum to NEAR, recipient = `alice.near`, `msg = ""`.
2. USDC admin blacklists `alice.near` on the NEAR USDC contract.
3. Relayer calls `fin_transfer` with correct proof and storage deposit actions.
4. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer(transfer_id)` commits — transfer ID is now in `finalised_transfers`.
   - `send_tokens` schedules `ft_transfer(alice.near, 1000, None)`.
5. `ft_transfer` panics (blacklisted recipient) — promise result = `Failed`.
6. `fin_transfer_send_tokens_callback` runs with `is_ft_transfer_call = false`:
   - `is_refund_required(false)` returns `false` without reading the promise result.
   - Fee is sent to relayer; `FinTransferEvent` is emitted.
7. 1000 USDC remain locked in the bridge. Re-submitting the proof fails with replay rejection. Funds are permanently frozen.

A local integration test can reproduce this by deploying a mock FT contract whose `ft_transfer` always panics, then executing the full `fin_transfer` flow and asserting that `finalised_transfers` contains the transfer ID while the recipient balance remains zero.