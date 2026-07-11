### Title
Misleading `burn_account_id` Parameter in `burn()` Emits False `FtBurn` Event Attribution — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `burn` function in the nBTC token contract accepts a `burn_account_id` parameter that is **never used in the actual token withdrawal**. The real burn is executed against `self.bridge_id`, while `burn_account_id` is only referenced in the `FtBurn` event emission. This causes every withdrawal to emit a `FtBurn` event with a false `owner_id`, misattributing the burn to the user's account rather than the bridge's account where the tokens actually reside at burn time.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, the `burn` function signature is:

```rust
pub fn burn(
    &mut self,
    burn_account_id: AccountId,
    burn_amount: U128,
    relayer_account_id: AccountId,
    relayer_fee: U128,
)
```

The actual token destruction is performed against `self.bridge_id`:

```rust
self.token
    .internal_withdraw(&self.bridge_id, burn_amount.into());
``` [1](#0-0) 

But `burn_account_id` is only consumed in the event:

```rust
near_contract_standards::fungible_token::events::FtBurn {
    owner_id: &burn_account_id,
    amount: burn_amount,
    memo: None,
}
.emit();
``` [2](#0-1) 

The withdrawal flow works as follows: the user calls `ft_transfer_call` on the nBTC contract, which moves their tokens to the bridge's balance. The bridge then calls `burn(user_account_id, amount, ...)` to destroy those tokens from its own balance. The `internal_withdraw` correctly targets `self.bridge_id` (where the tokens now live), but the `FtBurn` event incorrectly declares `owner_id` as the user's account — an account that no longer holds those tokens at the time of the burn. [3](#0-2) 

---

### Impact Explanation

**Low.** Every successful withdrawal emits a `FtBurn` event with a false `owner_id`. The NEP-141 `FtBurn` event is the canonical on-chain signal used by indexers, block explorers, wallets, and DeFi protocols to track token supply and user-level burn attribution. Emitting it with the wrong account means:

- Off-chain accounting systems will record that the user burned tokens directly, when in fact the bridge burned them from its own balance.
- Any protocol or indexer that tracks per-account burn history will have permanently incorrect data for every withdrawal.
- The discrepancy is not correctable after the fact since events are immutable on-chain records.

No direct theft or loss of funds occurs because the actual `internal_withdraw` amount and target are correct. This is a publicly reachable invariant violation in the production token path without direct theft.

---

### Likelihood Explanation

**High.** This is triggered on every single withdrawal finalization. The bridge always passes the withdrawing user's account as `burn_account_id`, and the mismatch between the event's `owner_id` and the actual account debited (`self.bridge_id`) is structural and unconditional. No special attacker action is required — normal bridge usage is sufficient to trigger it continuously.

---

### Recommendation

Use `burn_account_id` in the `internal_withdraw` call instead of `self.bridge_id`, or remove the parameter and document that the burn always comes from the bridge's custodial balance. The cleanest fix consistent with the actual token flow (bridge holds tokens during withdrawal) is to remove `burn_account_id` from the public interface and emit the event with `owner_id: &self.bridge_id`:

```rust
self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
near_contract_standards::fungible_token::events::FtBurn {
    owner_id: &self.bridge_id,
    amount: burn_amount,
    memo: None,
}.emit();
```

If the intent is to attribute the burn to the original user for indexer purposes, the tokens should instead be burned directly from `burn_account_id` (requiring the bridge to not pre-collect them, or to pass them back first), which would require a broader flow change.

---

### Proof of Concept

1. User holds 100,000 sat of nBTC and initiates a withdrawal by calling `ft_transfer_call` on the nBTC contract, transferring their tokens to the bridge's balance.
2. The bridge processes the withdrawal and eventually calls `burn(user.near, 100000, relayer.near, 500)` on the nBTC contract.
3. `internal_withdraw(&self.bridge_id, 100000)` executes correctly — the bridge's balance is reduced by 100,000.
4. The `FtBurn` event is emitted with `owner_id = "user.near"` and `amount = 100000`.
5. Any indexer consuming this event records that `user.near` burned 100,000 sat — but `user.near`'s balance was already reduced to zero by `ft_transfer_call` in step 1. The bridge's balance was the actual source of the burn.
6. The on-chain `FtBurn` record is permanently incorrect for every withdrawal ever processed. [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
```
