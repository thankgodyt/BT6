The code path is concrete and traceable. Let me lay out the exact execution trace.

**Execution trace:**

1. Caller (registered nBTC holder) calls `ft_transfer(nbtc_contract_id, amount, Some("WITHDRAW_TO:addr"))` with 1 yoctoNEAR attached.

2. The guard at lines 185–188 is satisfied: `receiver_id == env::current_account_id()` AND memo starts with `WITHDRAW_MEMO_PREFIX`. [1](#0-0) 

3. `read_withdraw_relayer_address()` returns `None` (storage key absent). The inner `if let Some(...)` branch is skipped. [2](#0-1) 

4. Execution falls through to line 195: `self.token.ft_transfer(receiver_id, amount, memo)` — where `receiver_id` is now `env::current_account_id()` (the nBTC contract itself). [3](#0-2) 

5. The NEP-141 `FungibleToken::ft_transfer` calls `internal_transfer`, which calls `internal_deposit(env::current_account_id(), amount)`. The standard implementation panics with `"The account is not registered"` because the nBTC contract's own account is never registered as a token holder — only `bridge_id` is registered at construction. [4](#0-3) 

**The precondition is realistic:** `migrate_from_poa` always writes `WITHDRAW_RELAYER_ADDRESS` during migration, but a fresh `new()` deployment does not — the relayer must be set separately via `set_withdraw_relayer_address`, which is a distinct controller call. Any window between deployment and that call, or any deliberate clearing of the key, opens this path. [5](#0-4) 

---

### Title
Unguarded fallthrough in `ft_transfer` panics when withdraw relayer is unset, breaking the legacy Near Intents withdrawal path — (`contracts/nbtc/src/lib.rs`)

### Summary
When `WITHDRAW_RELAYER_ADDRESS` is absent, `ft_transfer` called with `receiver_id = env::current_account_id()` and a `WITHDRAW_TO:` memo silently falls through and attempts to credit the nBTC contract itself as a token receiver. Because the contract is not registered as a token holder, the NEP-141 `internal_deposit` panics, reverting the caller's transaction.

### Finding Description
`ft_transfer` intercepts the legacy Near Intents withdrawal pattern (receiver = self, memo prefix `WITHDRAW_TO:`). When the relayer is configured, it redirects the transfer to the relayer. When the relayer is absent, the `if let Some(...)` guard silently falls through to the generic `self.token.ft_transfer(receiver_id, amount, memo)` at line 195, passing `env::current_account_id()` as the receiver. The NEP-141 standard `FungibleToken::internal_deposit` requires the receiver to be a registered account; the nBTC contract itself is never registered (only `bridge_id` is registered at init), so the call panics unconditionally. [6](#0-5) 

### Impact Explanation
Any registered nBTC holder who attempts the legacy Near Intents withdrawal path (`ft_transfer` to the contract with `WITHDRAW_TO:` memo) while the relayer is unset receives a panic revert. Their tokens are not lost (the transaction reverts), but the withdrawal path is entirely non-functional for all users during that window. The invariant that a public `ft_transfer` with valid sender balance must not panic is violated.

### Likelihood Explanation
The relayer is not set by the `new()` constructor — it requires a separate privileged `set_withdraw_relayer_address` call. Any deployment gap, key rotation, or accidental omission creates the vulnerable window. The trigger requires only a registered nBTC holder and 1 yoctoNEAR — no privilege needed.

### Recommendation
Replace the silent fallthrough with an explicit guard:

```rust
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    let withdraw_relayer = Self::read_withdraw_relayer_address()
        .unwrap_or_else(|| env::panic_str("Withdraw relayer not configured"));
    return self.token.ft_transfer(withdraw_relayer, amount, memo);
}
self.token.ft_transfer(receiver_id, amount, memo);
```

This surfaces a clear, actionable error instead of an opaque panic from the token internals.

### Proof of Concept
1. Deploy nBTC with `new(controller, bridge_id, ...)` — do **not** call `set_withdraw_relayer_address`.
2. Register a user account via `storage_deposit` and mint tokens to it.
3. Call `ft_transfer(nbtc_contract_id, 1, Some("WITHDRAW_TO:bc1qxxx"))` with 1 yoctoNEAR from the user.
4. Observe: transaction panics with `"The account is not registered"` (from NEP-141 `internal_deposit`).
5. Confirm: user balance unchanged (revert), withdrawal path non-functional.

### Citations

**File:** contracts/nbtc/src/lib.rs (L86-89)
```rust
        contract
            .token
            .internal_register_account(&contract.bridge_id);

```

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L324-328)
```rust
    pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
        self.assert_controller();

        env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
    }
```

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
