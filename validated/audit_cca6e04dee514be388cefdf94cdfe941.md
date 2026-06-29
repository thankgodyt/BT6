Audit Report

## Title
Silent Fall-Through in Legacy `ft_transfer` Branch Permanently Freezes Caller's Tokens — (`near/omni-token/src/lib.rs`)

## Summary
When `ft_transfer` is called with `receiver_id == current_account_id()` and a memo prefixed `WITHDRAW_TO:`, but `withdraw_relayer_address` is unset, the inner `if let` does not match and execution falls through to an unconditional `self.token.ft_transfer(receiver_id, amount, memo)` — transferring tokens into the token contract's own FT balance. No on-chain function can subsequently reduce that balance, making the loss permanent.

## Finding Description
The `FungibleTokenCore::ft_transfer` implementation at lines 194–207 of `near/omni-token/src/lib.rs` contains the following logic:

```rust
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
        return self.token.ft_transfer(withdraw_relayer, amount, memo);
    }
    // ← no else/panic; falls through
}
self.token.ft_transfer(receiver_id, amount, memo); // receiver_id == current_account_id()
```

When `read_withdraw_relayer_address()` returns `None`, the inner `if let` arm is skipped with no `else` branch or `panic!`. Execution reaches the unconditional `self.token.ft_transfer(receiver_id, amount, memo)` where `receiver_id` is still `env::current_account_id()`. The NEAR FT standard's `internal_transfer` only requires `predecessor_account_id != receiver_id`; since the caller (attacker) and the token contract are distinct accounts, this check passes and the transfer succeeds — crediting the token contract's own FT balance.

The `burn()` function at lines 146–151 calls `self.token.internal_withdraw(&env::predecessor_account_id(), amount.into())`, withdrawing from the *caller's* balance, not the contract's own balance. The `storage_unregister` implementation at lines 262–265 delegates to `self.token.internal_storage_unregister(force)`, which uses `env::predecessor_account_id()` as the account to unregister — meaning the token contract itself would need to be the transaction signer, which is not achievable through any standard external call. No `ft_on_transfer` implementation exists in `OmniToken`. The only indirect path is `attach_full_access_key` (lines 82–85), which requires the controller to add an off-chain key and manually sign a transaction from the contract account — not an on-chain recovery function.

## Impact Explanation
Tokens transferred into the token contract's own FT balance are irrecoverable through any on-chain call sequence available to users, the controller, or any admin role. This constitutes **permanent freezing of bridged funds**, matching the critical impact scope: *permanent freezing of bridged tokens across NEAR flows*.

## Likelihood Explanation
- `WITHDRAW_TO:` is the documented Near Intents legacy memo prefix; users migrating from that system are likely to use it.
- `withdraw_relayer_address` may be unset during deployment windows, contract upgrades, or migrations — a realistic operational state.
- `storage_deposit` is permissionless (lines 248–255); any attacker can register the token contract's own account before triggering the transfer.
- The call requires only 1 yoctoNEAR attached — a standard, low-friction operation with no special privileges.
- The condition is fully attacker-controlled and repeatable.

## Recommendation
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

This ensures the legacy path either routes correctly or reverts atomically, never silently depositing tokens into the contract itself.

## Proof of Concept
1. Deploy `OmniToken` without calling `set_withdraw_relayer_address` (so `read_withdraw_relayer_address()` returns `None`).
2. Call `storage_deposit(Some(token_contract_id), None)` with sufficient NEAR to register the token contract's own FT account — a permissionless call.
3. Mint tokens to the attacker account via the controller.
4. Call `ft_transfer(token_contract_id, 50, Some("WITHDRAW_TO:attacker_eth_addr"))` with 1 yoctoNEAR attached from the attacker account.
5. Assert `ft_balance_of(token_contract_id) == 50` and `ft_balance_of(attacker) == 0`.
6. Confirm that no sequence of on-chain calls (`burn`, `storage_unregister`, `ft_transfer`, `ft_transfer_call`) can reduce `ft_balance_of(token_contract_id)` — tokens are permanently frozen.