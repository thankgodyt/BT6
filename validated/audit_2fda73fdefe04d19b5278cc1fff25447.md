### Title
`withdraw_rbf` Reverts When Bitcoin Network Fees Exceed `max_btc_gas_fee`, Blocking User Self-Rescue of Stuck Withdrawals — (File: `contracts/satoshi-bridge/src/psbt.rs`, `contracts/satoshi-bridge/src/rbf/withdraw.rs`)

---

### Summary

The `check_withdraw_psbt` function enforces a hard upper bound (`max_btc_gas_fee`) on Bitcoin gas fees. This check is applied uniformly to both initial withdrawals **and** user-initiated RBF (Replace-By-Fee) transactions. When Bitcoin network fees spike above `max_btc_gas_fee`, a user whose withdrawal is already pending cannot accelerate it via `withdraw_rbf` — the call reverts. The user's nBTC remains locked inside the bridge until a privileged operator intervenes to cancel the withdrawal. The operator's `cancel_withdraw` path explicitly bypasses the same gas-fee ceiling, creating an asymmetry that leaves ordinary users with no self-rescue path.

---

### Finding Description

**Root cause — `check_withdraw_psbt` enforces `max_btc_gas_fee` on RBF:**

`check_withdraw_psbt` in `psbt.rs` unconditionally requires:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!(
        "Invalid gas fee ({}). valid range: [{}, {}].",
        gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
    )
);
``` [1](#0-0) 

**User RBF path calls this check without exception:**

`withdraw_rbf` (public, unprivileged) → `withdraw_rbf_chain_specific` → `internal_withdraw_rbf` → `check_withdraw_rbf_psbt_valid` → `check_withdraw_psbt`.

`check_withdraw_rbf_psbt_valid` delegates directly to `check_withdraw_psbt` with the original vUTXOs and amounts:

```rust
let (_, _, actual_received_amount, gas_fee) = self.check_withdraw_psbt(
    withdraw_rbf_psbt,
    target_address,
    &withdraw_change_address_script_pubkey,
    &original_tx_btc_pending_info.vutxos,
    original_tx_btc_pending_info.transfer_amount,
    original_tx_btc_pending_info.withdraw_fee,
);
``` [2](#0-1) 

There is no `is_cancel`-style bypass for the user RBF path; the `max_btc_gas_fee` ceiling is always enforced.

**Operator `cancel_withdraw` explicitly skips the same ceiling:**

`cancel_withdraw` (DAO/Operator-only) calls `check_psbt_output_all_change_address` with `is_cancel = true`, which skips the gas-fee range check:

```rust
if !is_cancel {
    require!(
        gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
        ...
    );
}
``` [3](#0-2) 

This creates a direct asymmetry: the operator can always cancel at any fee level, but the user cannot RBF above `max_btc_gas_fee`.

**`rbf_num_limit` compounds the problem:**

Even before fees spike, each user RBF attempt is counted against `rbf_num_limit`. Once the limit is reached, further `withdraw_rbf` calls revert with "Exceed rbf_num_limit":

```rust
if !is_cancel {
    require!(
        rbf_txs.len() <= self.internal_config().rbf_num_limit.into(),
        "Exceed rbf_num_limit"
    );
}
``` [4](#0-3) 

Cancel RBF bypasses this limit (`is_cancel = true`), but that path is operator-only.

---

### Impact Explanation

When a user's withdrawal transaction is pending (nBTC already transferred to the bridge via `ft_transfer_call`) and Bitcoin network fees spike above `max_btc_gas_fee`:

1. The original low-fee transaction will not confirm.
2. Every `withdraw_rbf` call reverts — the user has no self-rescue path.
3. The user's nBTC is held inside the bridge contract indefinitely.
4. Recovery requires a privileged operator to call `cancel_withdraw`, which returns the nBTC (minus gas fee).

This is a **stuck bridge state requiring operator intervention** — a medium-severity impact per the allowed scope. If the operator is slow, unavailable, or the DAO governance is delayed, the user's funds remain locked for an extended and unbounded period.

---

### Likelihood Explanation

Bitcoin fee spikes are a well-documented, recurring market event (e.g., Ordinals inscription waves, halving periods). The `max_btc_gas_fee` is a static config value set at deployment or via governance update. Any period where the mempool fee rate exceeds this configured ceiling — even transiently — triggers the revert for every in-flight withdrawal attempting RBF. This is a realistic, non-exotic condition.

---

### Recommendation

Apply the `max_btc_gas_fee` ceiling only to **initial** withdrawal PSBT construction, not to user-initiated RBF. For RBF, the relevant safety invariant is that the new gas fee exceeds the previous one (already enforced by Bitcoin's RBF rules and the `max_gas_fee` tracking in `OriginalState`), not that it stays below a static ceiling. Concretely:

- Add an `is_rbf: bool` parameter to `check_withdraw_psbt`, or
- Extract the gas-fee range check into a separate function called only from the initial withdrawal path.

Alternatively, allow `withdraw_rbf` to exceed `max_btc_gas_fee` up to a separate, higher `max_rbf_gas_fee` config value, giving users a meaningful self-rescue window during fee spikes.

---

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC contract with a `WithdrawMsg`. The bridge accepts the transfer and creates a `BTCPendingInfo` with `state = WithdrawOriginal(PendingSign)`. nBTC is now held by the bridge.
2. The bridge signs and broadcasts the BTC transaction with `gas_fee = config.max_btc_gas_fee` (the maximum allowed at the time).
3. Bitcoin mempool fees spike; the transaction sits unconfirmed.
4. User calls `withdraw_rbf` with a new PSBT where `gas_fee > config.max_btc_gas_fee`.
5. `check_withdraw_rbf_psbt_valid` → `check_withdraw_psbt` → `require!(gas_fee <= config.max_btc_gas_fee, ...)` — **reverts**.
6. User's nBTC remains locked in the bridge. The user has no further recourse.
7. Only a DAO/Operator calling `cancel_withdraw` (which passes `is_cancel = true` to `check_psbt_output_all_change_address`, bypassing the ceiling) can unblock the user. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L152-160)
```rust
        if !is_cancel {
            require!(
                gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
                format!(
                    "Invalid gas fee ({}). valid range: [{}, {}].",
                    gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
                )
            );
        }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L252-258)
```rust
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L23-31)
```rust
        let (_, _, actual_received_amount, gas_fee) = self.check_withdraw_psbt(
            withdraw_rbf_psbt,
            target_address,
            &withdraw_change_address_script_pubkey,
            &original_tx_btc_pending_info.vutxos,
            original_tx_btc_pending_info.transfer_amount,
            original_tx_btc_pending_info.withdraw_fee,
        );
        (actual_received_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/rbf/mod.rs (L36-41)
```rust
        if !is_cancel {
            require!(
                rbf_txs.len() <= self.internal_config().rbf_num_limit.into(),
                "Exceed rbf_num_limit"
            );
        }
```
