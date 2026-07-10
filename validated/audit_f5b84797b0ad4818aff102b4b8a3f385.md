### Title
Unguarded `storage_unregister(force: true)` Permanently Burns nBTC Without Releasing BTC — (`File: contracts/nbtc/src/lib.rs`)

### Summary

Any nBTC holder can call `storage_unregister(force: Some(true))` directly on the nBTC token contract to destroy their entire nBTC balance. This bypasses the bridge's controlled `burn` path entirely. The corresponding BTC remains permanently locked in the bridge's UTXOs, breaking the backed-supply invariant: the bridge holds more BTC than there are nBTC tokens in existence.

### Finding Description

The nBTC token contract implements `StorageManagement` by delegating to the NEAR SDK's standard `FungibleToken::internal_storage_unregister`. When `force: Some(true)` is passed, the SDK unregisters the account and destroys (burns) its entire token balance by reducing `total_supply` — without calling the bridge's `burn` function or notifying the bridge in any way.

The `storage_unregister` implementation in the nBTC contract contains no guard against this: [1](#0-0) 

The `#[allow(unused_variables)]` annotation on the destructured `balance` field is a visible signal that the non-zero balance case is silently discarded rather than rejected or routed through the bridge.

By contrast, the only legitimate burn path is the bridge-controlled `burn` function, which is gated by `assert_bridge()` and is only called after on-chain withdrawal verification: [2](#0-1) 

The bridge's `verify_withdraw` / `verify_withdraw_v2` flow calls `burn` only after a BTC transaction is confirmed on-chain, ensuring BTC is released before nBTC is destroyed: [3](#0-2) 

`storage_unregister(force: true)` completely sidesteps this flow.

### Impact Explanation

- The user's nBTC balance is permanently destroyed (total supply decreases).
- No BTC withdrawal is triggered; the corresponding BTC remains locked in the bridge's UTXOs forever.
- The bridge's BTC holdings now exceed the nBTC total supply — the backed-supply invariant is broken below parity.
- The destroyed nBTC can never be re-minted (minting requires a new on-chain BTC deposit proof).
- This is a self-inflicted but protocol-level accounting break: the bridge's BTC reserve is permanently inflated relative to circulating nBTC.

**Impact class:** Medium — permanent burning below backed supply; stuck bridge funds requiring no operator intervention to trigger but impossible to recover without a migration.

### Likelihood Explanation

- The call requires no privilege: any nBTC holder can invoke `storage_unregister(force: Some(true))` on the nBTC contract directly.
- It requires only a 1 yoctoNEAR attached deposit (standard NEP-145 requirement).
- A user who loses their NEAR account key and wants to "clean up" storage, or a malicious actor deliberately griefing the protocol's accounting, can trigger this.
- The NEAR ecosystem has tooling (NEAR CLI, wallets) that exposes `storage_unregister` as a standard call, lowering the bar further.

### Recommendation

Override `storage_unregister` in the nBTC contract to reject any call where the account's nBTC balance is non-zero, regardless of the `force` flag. Burning nBTC must only be possible through the bridge's controlled `burn` path (after on-chain BTC withdrawal verification). A minimal fix:

```rust
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    let account_id = env::predecessor_account_id();
    let balance = self.token.ft_balance_of(account_id.clone());
    require!(
        balance.0 == 0,
        "Cannot unregister account with non-zero nBTC balance; withdraw via bridge first"
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

1. Alice deposits 0.01 BTC into the bridge and receives 1,000,000 nBTC (satoshis) on NEAR.
2. Alice calls `storage_unregister(force: Some(true))` on the nBTC contract with 1 yoctoNEAR attached.
3. The NEAR SDK's `internal_storage_unregister` removes Alice's account and burns her 1,000,000 nBTC balance — `ft_total_supply` decreases by 1,000,000.
4. The bridge contract is never called; no BTC withdrawal is initiated.
5. Alice's 0.01 BTC remains locked in the bridge's UTXO set permanently.
6. The bridge now holds more BTC than the nBTC total supply reflects, breaking the 1:1 backing invariant. [1](#0-0) [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L254-262)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-250)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
        self.internal_verify_withdraw_entry(
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
        )
    }
```
