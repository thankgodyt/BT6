### Title
Unhandled `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Locks Bridged Tokens — (File: `near/omni-bridge/src/lib.rs`)

### Summary

When `fin_transfer` finalizes a cross-chain transfer to a NEAR recipient using a plain `ft_transfer` (empty `msg`), the callback `fin_transfer_send_tokens_callback` never checks whether the token transfer actually succeeded. If `ft_transfer` fails for any reason, the `locked_tokens` accounting is not restored, the transfer is permanently recorded as finalised, and the bridged tokens are irreversibly locked inside the bridge contract with no recovery path.

### Finding Description

The `process_fin_transfer_to_near` function unlocks tokens from the origin chain, marks the transfer as finalised in `finalised_transfers`, then calls `send_tokens` chained to `fin_transfer_send_tokens_callback`:

```rust
// near/omni-bridge/src/lib.rs:1881-1885
let lock_actions = vec![self.unlock_tokens_if_needed(
    transfer_message.get_origin_chain(),
    &token,
    transfer_message.amount.0,
)];
```

```rust
// near/omni-bridge/src/lib.rs:1957-1977
self.send_tokens(token.clone(), recipient, U128(...), &msg)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
            .fin_transfer_send_tokens_callback(
                transfer_message,
                &fee_recipient,
                !msg.is_empty(),   // ← is_ft_transfer_call
                predecessor_account_id,
                lock_actions,
            ),
    )
```

When `msg` is empty, `send_tokens` issues a plain `ft_transfer` and `is_ft_transfer_call` is passed as `false`. The callback's entire failure-detection logic is gated on that flag:

```rust
// near/omni-bridge/src/lib.rs:1784-1803
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            ...
        }
    } else {
        // Not ft_transfer_call: don't refund
        false   // ← always false; promise result is never inspected
    }
}
```

When `is_ft_transfer_call = false`, `is_refund_required` returns `false` unconditionally — it never reads the promise result. Consequently, `fin_transfer_send_tokens_callback` always takes the success branch:

```rust
// near/omni-bridge/src/lib.rs:1702-1718
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);   // ← never reached for plain ft_transfer
    self.remove_fin_transfer(...);
    ...
} else {
    // fee dispatch + success log — executed even on ft_transfer failure
}
```

If `ft_transfer` fails (promise result is `Err`), the callback still takes the `else` branch: `revert_lock_actions` is never called, the `finalised_transfers` entry is never removed, and the tokens remain in the bridge contract with no accounting entry pointing to them.

### Impact Explanation

- The `locked_tokens` counter for the origin chain is permanently decremented even though the tokens were never delivered.
- The transfer ID is recorded in `finalised_transfers`, making replay impossible.
- The actual token balance remains in the bridge contract but is unaccounted for — no future operation can release it.
- Result: **permanent freezing of bridged funds** for every transfer that hits this path.

### Likelihood Explanation

The most direct attacker-controlled path: a user who controls the NEAR recipient account registers storage for the token, waits for a relayer to call `fin_transfer` (storage check passes), then calls `storage_unregister` on the token contract in the same block before the `ft_transfer` cross-contract call is processed. The `ft_transfer` fails, but the callback takes the success path. The attacker sacrifices their source-chain tokens to permanently lock the corresponding NEAR-side tokens in the bridge, corrupting the `locked_tokens` invariant.

A non-adversarial path also exists: any transient failure of the token contract (e.g., a paused or buggy NEP-141 implementation) during `ft_transfer` produces the same permanent lock with no recovery.

### Recommendation

`fin_transfer_send_tokens_callback` must inspect the promise result regardless of whether `msg` is empty. Specifically, `is_refund_required` should also return `true` when `is_ft_transfer_call = false` and `env::promise_result_checked(0, ...)` returns `Err`. Alternatively, add a separate `#[callback_result]` parameter to `fin_transfer_send_tokens_callback` and revert lock actions whenever the promise failed:

```rust
// Pseudocode fix
if is_ft_transfer_call {
    Self::is_refund_required(true)
} else {
    // Also check plain ft_transfer result
    env::promise_result_checked(0, usize::MAX).is_err()
}
```

### Proof of Concept

1. Token `T` is a non-deployed (locked) NEP-141 token bridged from Ethereum; the bridge holds `N` units.
2. Attacker controls NEAR account `R` and registers storage for `T` on the token contract.
3. Attacker initiates a transfer of `N` tokens from Ethereum to `R`.
4. Relayer calls `fin_transfer`; `process_fin_transfer_to_near` runs:
   - `unlock_tokens_if_needed(Eth, T, N)` → `locked_tokens[(Eth, T)]` decremented by `N`.
   - `add_fin_transfer(transfer_id)` → transfer recorded as finalised.
   - Storage check passes