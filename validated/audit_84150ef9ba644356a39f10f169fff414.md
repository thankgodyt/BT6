### Title
Hardcoded Bitcoin-only chain detection in legacy config migration permanently corrupts chain state for non-Bitcoin deployments - (File: contracts/satoshi-bridge/src/legacy.rs)

### Summary
Both `From<ConfigV0> for Config` and `From<ConfigV1> for Config` migration implementations hardcode the resulting `chain` field to either `BitcoinTestnet` or `BitcoinMainnet` based solely on whether the NEAR account ID ends with `.testnet`. The bridge supports eight chains (`BitcoinMainnet`, `BitcoinTestnet`, `LitecoinMainnet`, `LitecoinTestnet`, `ZcashMainnet`, `ZcashTestnet`, `DogecoinMainnet`, `DogecoinTestnet`), but the migration code can only ever produce a Bitcoin chain value, permanently corrupting the on-chain config for any non-Bitcoin deployment that undergoes this migration path.

### Finding Description
In `contracts/satoshi-bridge/src/legacy.rs`, both migration converters contain identical hardcoded chain inference:

```rust
// From<ConfigV0> for Config  (lines 160-164)
let chain = if env::current_account_id().as_str().ends_with(".testnet") {
    crate::network::Chain::BitcoinTestnet
} else {
    crate::network::Chain::BitcoinMainnet
};
```

```rust
// From<ConfigV1> for Config  (lines 302-306)
let chain = if env::current_account_id().as_str().ends_with(".testnet") {
    crate::network::Chain::BitcoinTestnet
} else {
    crate::network::Chain::BitcoinMainnet
};
```

`ConfigV0` and `ConfigV1` have no `chain` field, so the migration must infer it. The inference is a two-outcome branch that can only produce Bitcoin variants. A Litecoin mainnet deployment (account ID `ltc-bridge.near`) would be assigned `BitcoinMainnet`; a Dogecoin testnet deployment (`doge-bridge.testnet`) would be assigned `BitcoinTestnet`. The resulting `Config` is then persisted to storage and used for all subsequent bridge operations.

The `chain` field drives every chain-sensitive operation in the bridge:
- `generate_utxo_chain_address` in `kdf.rs` calls `Address::from_pubkey(self.internal_config().chain.clone(), ...)`, which selects the address format (Bech32 HRP, P2PKH prefix, P2SH prefix) based on `chain`.
- `string_to_script_pubkey` and `target_script_pubkey` in `config.rs` call `Address::parse(address_string, chain)`, which validates and decodes addresses against the configured chain's byte prefixes.
- `WrappedTransaction::decode` in the deposit entry points passes `&self.internal_config().chain` to select the transaction parser.

After a bad migration, all of these operations silently use Bitcoin address encoding for a Litecoin or Dogecoin chain, producing structurally wrong deposit addresses and withdrawal outputs.

### Impact Explanation
After migration, the bridge's `chain` field is permanently set to a Bitcoin variant. Every deposit address derived by `get_user_deposit_address` will be a Bitcoin-format address (e.g., `bc1q…` or `1…`) instead of a Litecoin or Dogecoin address. Users who send funds to the displayed deposit address on the correct chain will send to an address that the bridge's UTXO set does not control, resulting in permanent loss of those funds. Withdrawal transactions constructed by the bridge will embed Bitcoin-format output scripts that are invalid on the actual chain, causing the signed PSBT to be unbroadcastable or rejected, permanently locking the bridge's UTXOs. The bridge enters a stuck state requiring operator intervention and a new migration, during which all user funds in transit are at risk.

### Likelihood Explanation
The `ContractDataV1` struct (which holds `LazyOption<ConfigV0>`) and the non-zcash variant of `ContractDataV2` (which holds `LazyOption<ConfigV1>`) are live migration paths in the current codebase. Any deployment that was initialized before the `chain` field was introduced and that has not yet been migrated past V1/V2 will exercise this code path on the next upgrade. Litecoin and Dogecoin are enumerated as first-class `Chain` variants alongside Bitcoin, making it plausible that deployments for those chains exist or will exist at a config version that triggers this path. The DAO triggers the migration in good faith; the bug is in the migration code itself, not in operator intent.

### Recommendation
Replace the two-outcome account-ID heuristic with an explicit chain parameter passed into the migration, or require the deployer to supply the correct `Chain` value as part of the upgrade call arguments. At minimum, add a compile-time or runtime assertion that panics if the inferred chain is not one of the two Bitcoin variants when the contract is known to be a Bitcoin deployment, preventing silent misconfiguration for other chains.

### Proof of Concept
1. Deploy `satoshi-bridge` for Litecoin mainnet with `ConfigV0` (no `chain` field), account ID `ltc-bridge.near`.
2. DAO calls the upgrade entry point, triggering `From<ConfigV0> for Config`.
3. `env::current_account_id()` returns `ltc-bridge.near`, which does not end with `.testnet`.
4. `chain` is set to `Chain::BitcoinMainnet` and written to storage.
5. A user calls `get_user_deposit_address`; the bridge derives a `bc1q…` Bitcoin address.
6. The user sends LTC to that address on the Litecoin network; the bridge never controls that UTXO and never mints nLTC. Funds are permanently lost.
7. Any pending withdrawal PSBT encodes a `bc1q…` output script, which is invalid on Litecoin; the signed transaction cannot be broadcast, locking the bridge's Litecoin UTXOs. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/legacy.rs (L160-164)
```rust
        let chain = if env::current_account_id().as_str().ends_with(".testnet") {
            crate::network::Chain::BitcoinTestnet
        } else {
            crate::network::Chain::BitcoinMainnet
        };
```

**File:** contracts/satoshi-bridge/src/legacy.rs (L302-306)
```rust
        let chain = if env::current_account_id().as_str().ends_with(".testnet") {
            crate::network::Chain::BitcoinTestnet
        } else {
            crate::network::Chain::BitcoinMainnet
        };
```

**File:** contracts/satoshi-bridge/src/network.rs (L17-28)
```rust
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chain {
    BitcoinMainnet,
    BitcoinTestnet,
    LitecoinMainnet,
    LitecoinTestnet,
    ZcashMainnet,
    ZcashTestnet,
    DogecoinMainnet,
    DogecoinTestnet,
}
```

**File:** contracts/satoshi-bridge/src/kdf.rs (L53-57)
```rust
    pub fn generate_utxo_chain_address(&self, path: &str) -> Address {
        let btc_public_key = self.generate_btc_public_key(path);
        Address::from_pubkey(self.internal_config().chain.clone(), btc_public_key)
            .expect("Invalid public key")
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L168-175)
```rust
    pub fn string_to_script_pubkey(&self, address_string: &str) -> ScriptBuf {
        let chain = self.get_utxo_network();

        Address::parse(address_string, chain)
            .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
            .script_pubkey()
            .expect("Failed to get script pubkey")
    }
```
