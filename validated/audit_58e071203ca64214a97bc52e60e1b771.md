### Title
Excess NEAR Attached Deposit Permanently Locked in Bridge Contract — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`, `contracts/satoshi-bridge/src/refund.rs`)

### Summary
Multiple public bridge entry points accept `env::attached_deposit() >= required_balance_for_*()` but never return the excess NEAR to the caller. The failure-path refund in `safe_mint_callback` explicitly transfers only the exact required balance, not the full `attached_deposit()`. Any NEAR sent above the minimum is permanently locked in the contract with no admin withdrawal path.

### Finding Description
Three public-facing functions use a `>=` guard on `attached_deposit` instead of strict equality:

**1. `internal_safe_verify_deposit_entry`** — `contracts/satoshi-bridge/src/btc_light_client/deposit.rs` line 182:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_safe_deposit(),
    "Insufficient deposit for storage"
);
```
The function accepts any amount ≥ the required storage balance. On the failure path, `safe_mint_callback` refunds only the exact required amount:
```rust
Promise::new(env::signer_account_id())
    .transfer(self.required_balance_for_safe_deposit())
    .detach();
```
The excess `attached_deposit() - required_balance_for_safe_deposit()` is never returned on either the success or failure path.

**2. `internal_request_refund`** — `contracts/satoshi-bridge/src/refund.rs` line 147:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
```

**3. `resolve_execute_refund_timelock`** — `contracts/satoshi-bridge/src/refund.rs` line 203:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
```

In all three cases, the contract has no mechanism to withdraw or return excess NEAR. The contract's general balance absorbs the overpayment permanently.

### Impact Explanation
Any NEAR sent above the minimum storage deposit is permanently locked in the bridge contract. There is no admin withdrawal function for excess NEAR deposits. On the `safe_verify_deposit` failure path, the refund is hardcoded to `required_balance_for_safe_deposit()`, not `env::attached_deposit()`, making the loss explicit and irreversible even when the bridge itself correctly detects and handles the failure.

This matches the **Low** allowed impact: "Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."

### Likelihood Explanation
Any unprivileged NEAR account calling `safe_verify_deposit`, `request_refund`, or `execute_refund` with an attached deposit larger than the minimum (e.g., due to wallet rounding, UI miscalculation, or manual transaction construction) will permanently lose the excess. The entry points are fully public and require no special role.

### Recommendation
Replace `>=` with `==` for all three storage-deposit guards, mirroring the fix applied in the referenced report:
```rust
require!(
    env::attached_deposit() == self.required_balance_for_safe_deposit(),
    "Attached deposit must equal required storage balance"
);
```
Alternatively, refund the full `env::attached_deposit()` (not just the required amount) in all failure paths, and add a DAO-gated function to sweep any accidentally accumulated excess NEAR.

### Proof of Concept
1. User calls `safe_verify_deposit` with `attached_deposit = required_balance_for_safe_deposit() + 1_000_000_000_000_000_000_000_000` (1 extra NEAR).
2. The `>=` check at line 182 passes.
3. The bridge proceeds; suppose the mint fails (e.g., recipient account not registered).
4. `safe_mint_callback` fires and executes:
   ```rust
   Promise::new(env::signer_account_id())
       .transfer(self.required_balance_for_safe_deposit())
       .detach();
   ``` [1](#0-0) 
5. The user receives back only `required_balance_for_safe_deposit()`. The extra 1 NEAR is absorbed into the contract balance with no recovery path.

The same scenario applies to `internal_request_refund` and `resolve_execute_refund_timelock`, where no refund of any kind is issued for the storage deposit, making any overpayment immediately and permanently lost. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L181-184)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L453-455)
```rust
            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L202-205)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```
