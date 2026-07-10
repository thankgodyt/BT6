### Title
Off-by-One Boundary Check in `get_confirmations` Assigns Boundary-Amount Deposits to Wrong Confirmation Tier - (File: contracts/satoshi-bridge/src/config.rs)

### Summary
The `get_confirmations` function in `Config` uses a strict `>` comparison instead of `>=` when iterating over sorted upper-bound keys of `confirmations_strategy`. A deposit whose satoshi amount exactly equals a configured tier boundary falls through to the next (higher) confirmation tier, requiring more block confirmations than the protocol intends for that amount.

### Finding Description
`Config::get_confirmations` implements a stepwise lookup over `confirmations_strategy`, a `HashMap<String, u8>` whose keys are documented as "Satoshi upper limit for amount checks → confirmations":

```rust
// contracts/satoshi-bridge/src/config.rs  lines 196-220
pub fn get_confirmations(&self, satoshi_amount: u128) -> u64 {
    ...
    keys.sort_unstable();
    for key in &keys {
        if *key > satoshi_amount {          // ← BUG: should be >=
            return u64::from(...);
        }
    }
    // falls through to max key
    ...
}
```

Because the keys are upper bounds, the correct predicate is `*key >= satoshi_amount`: "return the confirmations for the first tier whose ceiling covers this amount." With `>`, when `satoshi_amount == key`, the condition is false and the loop continues to the next tier (or falls through to the maximum key), assigning the deposit to a higher confirmation tier than intended.

Concrete example with `confirmations_strategy = {"1000000": 3, "10000000": 6}`:
- Deposit of 999,999 sat → key 1,000,000 > 999,999 → **3 confirmations** ✓
- Deposit of 1,000,000 sat → key 1,000,000 > 1,000,000 is **false** → key 10,000,000 > 1,000,000 → **6 confirmations** ✗ (should be 3)
- Deposit of 1,000,001 sat → key 1,000,000 > 1,000,001 is false → key 10,000,000 > 1,000,001 → **6 confirmations** ✓

The same function is called from every deposit and refund verification path:
- `internal_verify_deposit` / `internal_safe_verify_deposit` (called by `verify_deposit_v2`)
- `internal_verify_migrate_deposit_entry`
- `internal_request_refund`
- `internal_verify_refund_finalize`

### Impact Explanation
Any deposit or refund request whose satoshi amount exactly equals a configured tier boundary is silently assigned to the next confirmation tier. The relayer's proof submission is rejected by the BTC Light Client until the extra confirmations are reached. The deposit is not permanently lost, but it is temporarily stuck in a state where the protocol demands more confirmations than its own policy specifies. If the boundary coincides with a large jump (e.g., 3 → 12 confirmations), the delay is material. This is a publicly reachable invariant violation in the core deposit path with no direct theft.

**Impact: Low** — stuck-state / invariant violation in production bridge path without direct fund theft.

### Likelihood Explanation
Any unprivileged user or relayer submitting a deposit proof for a UTXO whose output value in satoshis exactly matches a configured `confirmations_strategy` key triggers the bug. The boundary values are operator-configured integers, so exact matches are possible whenever a user sends a round-satoshi amount (e.g., 0.01 BTC = 1,000,000 sat). No special access is required; the entry point is the public `verify_deposit_v2` call.

### Recommendation
Replace the strict `>` with `>=` in the loop condition so that a deposit amount equal to a tier's upper bound is correctly assigned to that tier:

```rust
// contracts/satoshi-bridge/src/config.rs
for key in &keys {
    if *key >= satoshi_amount {   // was: *key > satoshi_amount
        return u64::from(*self.confirmations_strategy.get(&key.to_string()).unwrap());
    }
}
```

### Proof of Concept
1. Operator configures `confirmations_strategy = {"1000000": 3, "10000000": 6}`.
2. User sends exactly 1,000,000 satoshis to their deposit address.
3. Relayer calls `verify_deposit_v2` once the transaction has 3 confirmations.
4. `get_confirmations(1_000_000)` iterates: `1_000_000 > 1_000_000` → false; `10_000_000 > 1_000_000` → true → returns **6**.
5. The BTC Light Client rejects the proof because only 3 confirmations are present; the deposit is stuck until 6 confirmations accumulate.
6. With the fix (`>=`), step 4 returns **3** and the proof is accepted immediately. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L60-61)
```rust
    // Satoshi upper limit for amount checks -> confirmations
    pub confirmations_strategy: HashMap<String, u8>,
```

**File:** contracts/satoshi-bridge/src/config.rs (L196-220)
```rust
    pub fn get_confirmations(&self, satoshi_amount: u128) -> u64 {
        require!(
            !self.confirmations_strategy.is_empty(),
            "confirmations_strategy is empty"
        );
        // The key is constrained to U64 during assignment, so it won't panic.
        let mut keys = self
            .confirmations_strategy
            .keys()
            .map(|k| k.parse::<u128>().unwrap())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        for key in &keys {
            if *key > satoshi_amount {
                return u64::from(*self.confirmations_strategy.get(&key.to_string()).unwrap());
            }
        }
        let max_key = keys.last().unwrap();
        u64::from(
            *self
                .confirmations_strategy
                .get(&max_key.to_string())
                .unwrap(),
        )
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L30-34)
```rust
        let confirmations = if deposit_msg.extra_msg.is_none() {
            self.get_confirmations(config, deposit_amount)
        } else {
            self.get_extra_msg_confirmations(config, deposit_amount)
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L86-87)
```rust
        let confirmations = self.get_confirmations(config, deposit_amount);
        let promise = self.verify_transaction_inclusion_promise(
```

**File:** contracts/satoshi-bridge/src/refund.rs (L166-168)
```rust
        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);
```
