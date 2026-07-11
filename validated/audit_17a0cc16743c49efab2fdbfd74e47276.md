### Title
Any nBTC Holder Can Permanently Burn Their Tokens via `storage_unregister`, Reducing Supply Below Backed BTC - (File: contracts/nbtc/src/lib.rs)

### Summary
The nBTC token contract exposes the standard NEP-141 `storage_unregister(force: Some(true))` function without any override or guard. Any token holder can call it to atomically destroy their entire nBTC balance and reduce `total_supply`, without triggering a BTC withdrawal. The corresponding BTC remains permanently locked in the bridge, creating a permanent supply/accounting mismatch where `total_supply` < BTC held by the bridge.

### Finding Description
The `storage_unregister` function in `contracts/nbtc/src/lib.rs` delegates unconditionally to `self.token.internal_storage_unregister(force)`:

```rust
#[payable]
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    #[allow(unused_variables)]
    if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
        log!("Closed @{} with {}", account_id, balance);
        true
    } else {
        false
    }
}
```

The near-contract-standards `FungibleToken::internal_storage_unregister` implementation, when called with `force: Some(true)`, removes the caller's account entry and subtracts their full balance from `total_supply`. No BTC withdrawal is initiated, no bridge state is updated, and no refund of the underlying BTC is possible.

By contrast, the legitimate `burn` path is correctly gated:

```rust
pub fn burn(...) {
    self.assert_bridge();   // only the bridge contract may call this
    self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
    ...
}
```

The `burn` function is only callable by the bridge contract (`assert_bridge()`), and it only burns from the bridge's own balance after a verified on-chain BTC withdrawal. `storage_unregister` bypasses all of this.

### Impact Explanation
Any nBTC holder can call `nbtc.storage_unregister({"force": true})` with 1 yoctoNEAR attached. This:
1. Permanently destroys their entire nBTC balance.
2. Permanently reduces `ft_total_supply()`.
3. Leaves the corresponding satoshis locked in the bridge's UTXO set forever — they can never be withdrawn because no pending withdrawal record exists.

The result is a permanent, irreversible state where `total_supply` of nBTC is less than the BTC held by the bridge. This matches the allowed impact: **Medium — permanent burning below backed supply**.

### Likelihood Explanation
The call is trivially reachable by any nBTC holder with no special permissions. It requires only 1 yoctoNEAR attached deposit (the `#[payable]` requirement). A user could trigger this accidentally (e.g., trying to reclaim storage) or deliberately. The function is part of the standard NEP-141 storage-management interface and is publicly documented, making it easy to discover.

### Recommendation
Override `storage_unregister` in the nBTC contract to reject any call where the caller's balance is non-zero, or reject all calls unconditionally (since nBTC accounts should only be closed through the bridge's withdrawal flow):

```rust
#[payable]
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    let account_id = env::predecessor_account_id();
    require!(
        self.token.ft_balance_of(account_id.clone()).0 == 0,
        "Cannot unregister nBTC account with non-zero balance; use the bridge withdrawal flow"
    );
    if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
        log!("Closed @{} with {}", account_id, balance);
        true
    } else {
        false
    }
}
```

### Proof of Concept
1. Alice deposits 0.01 BTC → bridge mints 1,000,000 satoshis of nBTC to Alice.
2. Alice calls `nbtc.storage_unregister({"force": true})` with 1 yoctoNEAR attached.
3. `internal_storage_unregister(Some(true))` removes Alice's account and subtracts 1,000,000 from `total_supply`.
4. `ft_total_supply()` is now 0 (or reduced by 1,000,000 if other holders exist).
5. The bridge's UTXO set still contains Alice's 0.01 BTC UTXO. No withdrawal was ever initiated. The BTC is permanently inaccessible.
6. Alice's BTC is permanently lost; the bridge's backed supply is permanently above `total_supply`. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/nbtc/src/lib.rs (L150-157)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L253-262)
```rust
    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
            log!("Closed @{} with {}", account_id, balance);
            true
        } else {
            false
        }
    }
```
