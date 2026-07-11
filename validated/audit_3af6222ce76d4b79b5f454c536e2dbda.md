### Title
Missing `bridge_id` Account Registration in `migrate_from_poa` Breaks Mint/Burn Operations — (File: `contracts/nbtc/src/migrate.rs`)

---

### Summary

The `migrate_from_poa` function in the `nbtc` contract migrates token state from a Near Intents PoA system to the new satoshi-bridge. Unlike the `new()` constructor, it omits the step that registers `bridge_id` in the `FungibleToken` account map. Because the new `bridge_id` (satoshi-bridge) was not part of the old PoA system, it is absent from the migrated token state. Any subsequent call to `safe_mint` or `burn` — both of which unconditionally call `internal_deposit`/`internal_withdraw` on the unregistered `bridge_id` — will panic, permanently breaking deposit and withdrawal flows unless a regular `mint` call with `protocol_fee > 0` happens first to auto-register the account.

---

### Finding Description

In `new()`, the constructor explicitly registers `bridge_id` in the token:

```rust
contract.token.internal_register_account(&contract.bridge_id);
``` [1](#0-0) 

In `migrate_from_poa`, this step is entirely absent. The function reads the old `NearIntentsState`, removes the `OWNABLE_KEY`, writes the `WITHDRAW_RELAYER_ADDRESS`, and constructs a new `Contract` — but never registers `bridge_id`:

```rust
let new_state = Self {
    controller,
    bridge_id,
    token: state.token,   // old token state; new bridge_id not present
    metadata: LazyOption::new(StorageKey::Metadata, Some(state.metadata.get())),
};
``` [2](#0-1) 

After migration, `safe_mint` unconditionally calls `self.token.internal_deposit(&self.bridge_id, amount.into())` before any account-existence check:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
``` [3](#0-2) 

NEAR's `FungibleToken::internal_deposit` calls `internal_unwrap_balance_of`, which panics with `"The account {} is not registered"` if the account is absent. The same applies to `burn`, which calls `self.token.internal_withdraw(&self.bridge_id, burn_amount.into())`: [4](#0-3) 

The only path that auto-registers `bridge_id` is `mint_inner`, called from `mint` only when `protocol_fee > 0`:

```rust
if protocol_fee.0 > 0 {
    self.mint_inner(&self.bridge_id.clone(), protocol_fee);
}
``` [5](#0-4) 

If `protocol_fee` is zero for all regular deposits (or if `safe_mint` or `burn` is invoked before any `mint` with `protocol_fee > 0`), `bridge_id` is never registered and both functions permanently panic.

---

### Impact Explanation

- **Safe deposits** (`safe_mint`): panic on `internal_deposit` to unregistered `bridge_id` → user BTC is locked in the bridge's UTXO pool with no nBTC minted.
- **Withdrawals** (`burn`): panic on `internal_withdraw` from unregistered `bridge_id` → user nBTC sent to the bridge via `ft_transfer_call` cannot be burned, and BTC cannot be released.
- **`ft_transfer_call` to bridge**: also fails because `bridge_id` is not a registered recipient in the token, blocking the withdrawal initiation path entirely.

If `protocol_fee == 0` for all deposits, `bridge_id` is never auto-registered and the bridge is permanently broken for safe deposits and withdrawals — matching the "stuck bridge state requiring operator intervention" and potentially "permanent locking of user funds" impact categories.

---

### Likelihood Explanation

`migrate_from_poa` is a one-time migration path from the Near Intents PoA token to the new satoshi-bridge. It is a planned operational step. The bug is silent at migration time and only surfaces on the first `safe_mint` or `burn` call. Any user who sends BTC to a safe-deposit address, or any user who initiates a withdrawal, immediately triggers the panic. No attacker action is required — ordinary bridge usage is sufficient.

---

### Recommendation

Add `bridge_id` account registration inside `migrate_from_poa`, mirroring what `new()` does:

```diff
 let new_state = Self {
     controller,
-    bridge_id,
+    bridge_id: bridge_id.clone(),
     token: state.token,
     metadata: LazyOption::new(StorageKey::Metadata, Some(state.metadata.get())),
 };
+new_state.token.internal_register_account(&bridge_id);
 new_state
``` [2](#0-1) 

---

### Proof of Concept

1. Deploy the old Near Intents PoA nbtc token with some token holders.
2. Deploy the new nbtc contract code and call `migrate_from_poa(controller, satoshi_bridge_id, withdraw_relayer)`.
3. The new contract state has `bridge_id = satoshi_bridge_id`, but `satoshi_bridge_id` is not in `token.accounts`.
4. Call `safe_mint(user_account, 1000, None)` from `satoshi_bridge_id` (the bridge).
5. Execution panics at `self.token.internal_deposit(&self.bridge_id, amount.into())` with `"The account satoshi_bridge_id is not registered"`.
6. Alternatively, have a user call `ft_transfer_call(satoshi_bridge_id, 500, None, withdraw_msg)` — this also panics because `satoshi_bridge_id` is not a registered recipient.
7. All safe deposits and withdrawals are permanently blocked until an operator manually registers `bridge_id` or a regular `mint` with `protocol_fee > 0` is executed.

### Citations

**File:** contracts/nbtc/src/lib.rs (L87-88)
```rust
            .token
            .internal_register_account(&contract.bridge_id);
```

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L137-139)
```rust
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
```

**File:** contracts/nbtc/src/lib.rs (L158-160)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
```

**File:** contracts/nbtc/src/migrate.rs (L65-72)
```rust
            let new_state = Self {
                controller,
                bridge_id,
                token: state.token,
                metadata: LazyOption::new(StorageKey::Metadata, Some(state.metadata.get())),
            };

            new_state
```
