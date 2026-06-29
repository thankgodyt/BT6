Now I have the full picture. Let me trace the exact code path.

### Title
Silent Fall-Through in Legacy `ft_transfer` Branch Permanently Freezes Caller's Tokens — (`near/omni-token/src/lib.rs`)

### Summary

When `ft_transfer` is called with `receiver_id == current_account_id` and a memo prefixed `WITHDRAW_TO:`, but no `withdraw_relayer_address` has been configured, the function silently falls through and transfers tokens **to the token contract itself**. No admin or controller function exists to recover those tokens, making the loss permanent.

### Finding Description

The legacy Near Intents bridging branch in `FungibleTokenCore::ft_transfer` reads:

```rust
// lib.rs:196-206
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
        return self.token.ft_transfer(withdraw_relayer, amount, memo);
    }
}
self.token.ft_transfer(receiver_id, amount, memo);  // ← falls through
``` [1](#0-0) 

When `read_withdraw_relayer_address()` returns `None`, the inner `if let` does not match, there is no `else`/`panic`, and execution falls through to the unconditional `self.token.ft_transfer(receiver_id, amount, memo)` on line 206 — where `receiver_id` is still `current_account_id()`. The NEAR FT standard's `internal_transfer` only requires `sender_id != receiver_id`; since the sender is the caller (predecessor) and the receiver is the token contract, that check passes and the transfer succeeds. [2](#0-1) 

**Pre-condition setup (fully attacker-controlled):**
- If the token contract's own account is not yet registered in FT storage, the attacker calls `storage_deposit(Some(token_contract_id), None)` first — a permissionless call anyone can make.
- `withdraw_relayer_address` is unset (either never configured, or the contract was recently deployed/migrated).

**No recovery path exists.** The only balance-reducing function is `burn()`:

```rust
// lib.rs:146-151
fn burn(&mut self, amount: U128) {
    self.assert_controller();
    self.token.internal_withdraw(&env::predecessor_account_id(), amount.into());
}
``` [3](#0-2) 

`burn()` withdraws from `env::predecessor_account_id()` — the controller's own balance — not from the token contract's balance. There is no `ft_on_transfer` implementation, no admin sweep function, and no other mechanism to move tokens out of the token contract's own FT balance. [4](#0-3) 

### Impact Explanation

Any user who calls `ft_transfer(token_contract_id, amount, Some("WITHDRAW_TO:..."))` while the relayer is unconfigured permanently loses `amount` tokens. The tokens are credited to the token contract's own FT balance with no on-chain recovery path. This matches the critical scope: **permanent freezing of bridged tokens**.

### Likelihood Explanation

- The `WITHDRAW_TO:` memo prefix is part of the documented Near Intents legacy flow; users migrating from that system are likely to use it.
- `withdraw_relayer_address` may be unset during deployment windows, contract upgrades, or migrations.
- The attacker (or any user) can permissionlessly register the token contract's storage account via `storage_deposit`, making the precondition trivially satisfiable.
- The call requires only 1 yoctoNEAR attached — a standard, low-friction operation.

### Recommendation

Replace the silent fall-through with an explicit panic when the legacy branch is entered but no relayer is configured:

```rust
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    let withdraw_relayer = Self::read_withdraw_relayer_address()
        .unwrap_or_else(|| env::panic_str("Withdraw relayer address not configured"));
    return self.token.ft_transfer(withdraw_relayer, amount, memo);
}
self.token.ft_transfer(receiver_id, amount, memo);
```

This ensures the legacy path either routes correctly or reverts, never silently depositing tokens into the contract itself.

### Proof of Concept

1. Deploy `OmniToken` without calling `set_withdraw_relayer_address`.
2. Call `storage_deposit(Some(token_contract_id), None)` with sufficient NEAR to register the token contract's own account.
3. Mint tokens to attacker account via the controller.
4. Call `ft_transfer(token_contract_id, 50, Some("WITHDRAW_TO:attacker_eth_addr"))` with 1 yoctoNEAR attached.
5. Assert `ft_balance_of(token_contract_id) == 50` and `ft_balance_of(attacker) == 0`.
6. Confirm no callable function can reduce `ft_balance_of(token_contract_id)` — tokens are permanently frozen.

### Citations

**File:** near/omni-token/src/lib.rs (L106-108)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```

**File:** near/omni-token/src/lib.rs (L194-207)
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

**File:** near/omni-token/src/lib.rs (L229-244)
```rust
#[near]
impl FungibleTokenResolver for OmniToken {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used_amount, _burned_amount) =
            self.token
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);

        used_amount.into()
    }
}
```
