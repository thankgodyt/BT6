### Title
`min_withdraw_amount` check in `ft_on_transfer` can permanently strand user nBTC below the withdrawal floor - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

---

### Summary

The `ft_on_transfer` entry point enforces `amount >= min_withdraw_amount` on every withdrawal attempt. Because the check is applied to the amount sent in a single call and the bridge has no mechanism to aggregate or sweep sub-minimum balances, a user who makes a partial withdrawal can be left with a remaining nBTC balance that is permanently non-redeemable via the bridge.

---

### Finding Description

In `ft_on_transfer`, before any withdrawal logic runs, the bridge asserts:

```rust
require!(
    amount >= self.internal_config().min_withdraw_amount,
    "Invalid amount"
);
``` [1](#0-0) 

`min_withdraw_amount` is a configurable field in `Config`: [2](#0-1) 

The check is applied to the raw `amount` argument of the single `ft_transfer_call` invocation. The bridge never inspects the caller's total nBTC balance, and there is no sweep or consolidation path that would let a user combine a sub-minimum balance with a new deposit in a single atomic call.

**Stuck-state scenario:**

1. Alice holds `min_withdraw_amount + X` nBTC, where `0 < X < min_withdraw_amount`.
2. Alice calls `ft_transfer_call` on the nBTC contract with `amount = min_withdraw_amount`. The check passes; the withdrawal proceeds normally.
3. Alice now holds exactly `X` nBTC.
4. Alice calls `ft_transfer_call` with `amount = X`. The check `X >= min_withdraw_amount` fails with `"Invalid amount"`.
5. Alice's `X` nBTC is permanently non-redeemable via the bridge unless she first acquires additional nBTC to bring the total above `min_withdraw_amount`.

The same outcome arises from the cancel-withdraw path: when `cancel_withdraw` is executed and the on-chain burn succeeds, the bridge refunds the user:

```rust
let refund = if btc_pending_info.is_cancel_withdraw_rbf() {
    btc_pending_info
        .transfer_amount
        .saturating_sub(btc_pending_info.withdraw_fee + btc_pending_info.burn_amount)
} else {
    0
};
``` [3](#0-2) 

If the original withdrawal was for exactly `min_withdraw_amount`, the refunded amount is `min_withdraw_amount - withdraw_fee - gas_fee`, which is strictly less than `min_withdraw_amount`. That refunded nBTC lands back in the user's wallet but immediately fails the minimum check on any subsequent withdrawal attempt.

---

### Impact Explanation

The user's nBTC tokens are not destroyed, but they become permanently non-redeemable through the bridge's only withdrawal path (`ft_on_transfer`). The user cannot convert the stranded nBTC back to native BTC without first acquiring additional nBTC externally. This is a publicly reachable stuck-state in the production withdrawal path with no operator intervention available to resolve it for the user.

**Impact: Low** — stuck-state / invariant violation in production bridge path without direct theft.

---

### Likelihood Explanation

The scenario is reachable by any unprivileged nBTC holder through ordinary use of `ft_transfer_call`. No special role, leaked key, or external dependency failure is required. It is triggered whenever a user's nBTC balance is not an exact multiple of `min_withdraw_amount` and they make a partial withdrawal. The cancel-withdraw variant additionally requires an operator action, but the partial-withdrawal variant is entirely self-inflicted and requires no privileged cooperation.

---

### Recommendation

Two complementary mitigations:

1. **Allow full-balance sweeps below the minimum.** If the amount sent equals the caller's entire nBTC balance and that balance is below `min_withdraw_amount`, permit the withdrawal provided it still exceeds the minimum economically viable Bitcoin output (i.e., covers the gas fee). This mirrors the common pattern of allowing a "withdraw all" even when the balance is below a normal floor.

2. **Validate the post-withdrawal remainder at the call site.** Before accepting the transfer, check whether the caller's remaining balance (queryable from the nBTC contract) would fall below `min_withdraw_amount` and, if so, require the user to withdraw the full balance in one call.

---

### Proof of Concept

```
State: Alice holds 1.5 * min_withdraw_amount nBTC.

Step 1 — Alice calls ft_transfer_call(amount = min_withdraw_amount):
  ft_on_transfer check: min_withdraw_amount >= min_withdraw_amount → PASS
  Withdrawal proceeds; Alice's wallet now holds 0.5 * min_withdraw_amount nBTC.

Step 2 — Alice calls ft_transfer_call(amount = 0.5 * min_withdraw_amount):
  ft_on_transfer check: 0.5 * min_withdraw_amount >= min_withdraw_amount → FAIL
  Error: "Invalid amount"

Result: Alice's 0.5 * min_withdraw_amount nBTC is permanently non-redeemable
        via the bridge without acquiring additional nBTC externally.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L30-33)
```rust
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L73-75)
```rust
    // The minimum amount allowed for the user to withdraw.
    #[serde(with = "u128_dec_format")]
    pub min_withdraw_amount: u128,
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L62-68)
```rust
        let refund = if btc_pending_info.is_cancel_withdraw_rbf() {
            btc_pending_info
                .transfer_amount
                .saturating_sub(btc_pending_info.withdraw_fee + btc_pending_info.burn_amount)
        } else {
            0
        };
```
