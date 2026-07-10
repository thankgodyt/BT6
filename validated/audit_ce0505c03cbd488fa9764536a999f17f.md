### Title
Hardcoded Non-Refundable NEAR Fees in Refund Path Have No Governance Update Mechanism - (File: contracts/satoshi-bridge/src/api/view.rs)

### Summary
`required_balance_for_execute_refund()` and `required_balance_for_request_refund()` return hardcoded NEAR amounts (1 NEAR and 2 NEAR respectively) that are permanently burned as anti-spam fees and cannot be updated by governance. Unlike all other protocol parameters, these values are not part of `Config` and are unreachable by `update_config()`. If NEAR price rises significantly, legitimate users with stuck BTC deposits cannot afford the non-refundable fees to recover their funds; if NEAR price drops significantly, the anti-spam protection weakens. There is no on-chain mechanism to correct either condition without a full contract upgrade.

### Finding Description
In `contracts/satoshi-bridge/src/api/view.rs`, two view functions return hardcoded NEAR amounts:

```rust
pub fn required_balance_for_execute_refund(&self) -> NearToken {
    NearToken::from_near(1)   // hardcoded, NOT refunded
}

pub fn required_balance_for_request_refund(&self) -> NearToken {
    NearToken::from_near(2)   // hardcoded, NOT refunded
}
```

These values are enforced as mandatory attached deposits in the production refund path:

- `internal_request_refund()` panics if `env::attached_deposit() < self.required_balance_for_request_refund()` — the 2 NEAR is consumed and never returned.
- `resolve_execute_refund_timelock()` panics if `env::attached_deposit() < self.required_balance_for_execute_refund()` — the 1 NEAR is consumed and never returned.

The `Config` struct (config.rs lines 47–121) contains every other tunable protocol parameter (`min_deposit_amount`, `min_withdraw_amount`, `min_btc_gas_fee`, `max_btc_gas_fee`, `refund_timelock_sec`, etc.), all updatable via the DAO-gated `update_config()` call. The refund NEAR fees are absent from `Config` entirely, so `update_config()` cannot touch them. No other management function in `management.rs` addresses them. The only remediation path is a full contract upgrade.

Additionally, `REQUIRED_BALANCE_FOR_DEPOSIT` (0.0012 NEAR) is a hardcoded compile-time constant with the same absence of governance control, though its storage-coverage role makes it less price-sensitive.

### Impact Explanation
The refund flow is the sole recovery mechanism for users whose BTC deposit was confirmed on-chain but never finalized (e.g., incorrect metadata, failed mint callback). A user in this situation must pay 2 NEAR (request) + 1 NEAR (execute) = 3 NEAR in non-refundable fees to recover their BTC.

NEAR has historically traded between ~$0.50 and ~$20. If NEAR reaches $20, the mandatory non-refundable cost to recover stuck BTC is $60. At $50 NEAR it is $150. Users holding small BTC deposits (e.g., 0.001 BTC ≈ $100 at $100k BTC) would rationally abandon their funds rather than pay the recovery fee, resulting in permanent effective locking of their BTC inside the bridge with no on-chain remedy. This is a stuck-state in the production bridge refund path without direct theft.

Conversely, if NEAR price collapses (e.g., to $0.10), 2 NEAR = $0.20, making the anti-spam protection negligible. While `request_refund` requires a valid BTC proof, an attacker who controls multiple small UTXOs at deposit addresses could flood `refund_requests` cheaply, bloating bridge state and potentially causing operator intervention to clear it.

### Likelihood Explanation
NEAR is a volatile asset with a documented price range of roughly 40× between its all-time low and high. The bridge is intended to be a long-lived protocol. The absence of any governance update path means the hardcoded values will inevitably become misaligned with market conditions over the protocol's lifetime. The refund path is permissionless and publicly reachable by any user who has sent BTC to a deposit address.

### Recommendation
Move the refund NEAR fee amounts into `Config` alongside the existing fee parameters:

```rust
pub struct Config {
    // ... existing fields ...
    pub required_balance_for_request_refund: NearToken,
    pub required_balance_for_execute_refund: NearToken,
}
```

Then expose them through `ConfigUpdate` so the DAO can adjust them via the existing `update_config()` governance function, mirroring how `min_btc_gas_fee` and `max_btc_gas_fee` are already handled. This is the same recommendation made in the reference report: governance-adjustable values rather than hardcoded constants, because token prices change significantly over time.

### Proof of Concept
1. User sends 0.001 BTC to a bridge deposit address with a malformed `deposit_msg` (e.g., a recipient account that does not exist on NEAR).
2. The relayer calls `verify_deposit_v2`; minting fails; the UTXO is recorded but no nBTC is issued.
3. NEAR price rises to $30. The user must now pay 2 NEAR ($60, non-refundable) to call `request_refund`, then 1 NEAR ($30, non-refundable) to call `execute_refund` — $90 total to recover ~$100 of BTC.
4. The user's BTC remains locked in the bridge. No DAO action can lower the fee without a full contract upgrade, because `required_balance_for_request_refund` and `required_balance_for_execute_refund` are not in `Config` and are unreachable by `update_config()`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/api/view.rs (L322-339)
```rust
    pub fn required_balance_for_execute_refund(&self) -> NearToken {
        // Measured real storage: ~0.012 NEAR (Bitcoin) up to ~0.134 NEAR (Zcash shielded,
        // whose pending info embeds the Orchard bundle). The deposit is NOT refunded, so
        // 1 NEAR covers the heaviest case and acts as an anti-spam fee on this
        // permissionless entrypoint — refunds are a rare, abnormal event anyway.
        NearToken::from_near(1)
    }

    pub fn required_balance_for_request_refund(&self) -> NearToken {
        // request_refund stores a RefundRequest holding the deposit tx_bytes verbatim, so
        // storage grows ~1:1 with tx size (measured: storage ≈ tx_bytes + ~442 bytes). A
        // normal deposit (1-2 inputs, ~500 bytes) costs ~0.005 NEAR, but tx_bytes is capped
        // at MAX_REQUEST_REFUND_TX_BYTES (200 KB) — at that worst case storage is ~2 NEAR.
        // We size the deposit to cover that worst case; for normal deposits the bulk of it
        // is an anti-spam fee on this permissionless entrypoint (the deposit is NOT refunded).
        // Refunds are a rare, abnormal event anyway.
        NearToken::from_near(2)
    }
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

**File:** contracts/satoshi-bridge/src/config.rs (L47-121)
```rust
pub struct Config {
    // The chain id: BitconMainnet/BitcoinTestnet/ZcashMainnet/ZcashTestnet etc
    pub chain: network::Chain,
    // The account id of btc light client contract
    pub btc_light_client_account_id: AccountId,
    // The account id of nbtc contract
    pub nbtc_account_id: AccountId,
    // The account id of chain signatures contract
    pub chain_signatures_account_id: AccountId,
    // The root public key of chain signatures contract
    pub chain_signatures_root_public_key: Option<PublicKey>,
    // The change address of BTC transaction
    pub change_address: Option<String>,
    // Satoshi upper limit for amount checks -> confirmations
    pub confirmations_strategy: HashMap<String, u8>,
    // The number of confirmations that need to be increased when a relayer not on the whitelist performs a verify.
    pub confirmations_delta: u8,
    // The number of confirmations that need to be increased when a relayer not on the extra msg whitelist performs a verify.
    pub extra_msg_confirmations_delta: u8,
    // Used to calculate the deposit fee.
    pub deposit_bridge_fee: BridgeFee,
    // Used to calculate the withdraw fee.
    pub withdraw_bridge_fee: BridgeFee,
    // The min amount must be met during verify_deposit, otherwise NBTC will not be minted for the user.
    #[serde(with = "u128_dec_format")]
    pub min_deposit_amount: u128,
    // The minimum amount allowed for the user to withdraw.
    #[serde(with = "u128_dec_format")]
    pub min_withdraw_amount: u128,
    // The minimum value requirement that change address must satisfy in BTC transaction.
    #[serde(with = "u128_dec_format")]
    pub min_change_amount: u128,
    // Used to limit the maximum value of change in specific situations.
    #[serde(with = "u128_dec_format")]
    pub max_change_amount: u128,
    // The min gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
    // The maximum number of inputs that can be used for a Withdraw.
    pub max_withdrawal_input_number: u8,
    // The maximum amount of change allowed during a Withdraw.
    pub max_change_number: u8,
    // The maximum number of inputs allowed during active UTXO management.
    pub max_active_utxo_management_input_number: u8,
    // The maximum number of outputs allowed during active UTXO management.
    pub max_active_utxo_management_output_number: u8,
    // When the number of UTXOs in the protocol is less than this configuration, UTXO management can be actively initiated.
    // The number of inputs in the managed PSBT must be less than the number of outputs.
    pub active_management_lower_limit: u32,
    // When the number of UTXOs in the protocol is greater than this configuration, UTXO management can be actively initiated.
    // The number of inputs in the managed PSBT must be greater than the number of outputs.
    pub active_management_upper_limit: u32,
    // When the number of UTXOs in the protocol is less than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be less than the number of changes.
    pub passive_management_lower_limit: u32,
    // When the number of UTXOs in the protocol is greater than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be greater than the number of changes.
    pub passive_management_upper_limit: u32,
    // The maximum number of transactions allowed to initiate RBF
    pub rbf_num_limit: u8,
    // If the transaction exceeds this configuration and has not been verified, the protocol will be allowed to cancel the transaction.
    pub max_btc_tx_pending_sec: u32,
    // UTXOs less than or equal to this amount are allowed to be merged through active management.
    pub unhealthy_utxo_amount: u64,
    // Timelock for refunds where `deposit_msg.refund_address` is pre-authorized.
    pub refund_timelock_sec: u64,
    // Timelock for refunds where the refund address comes from the request caller
    // (`deposit_msg.refund_address` was None). Must be >= `refund_timelock_sec`.
    pub unsafe_refund_timelock_sec: u64,
    #[cfg(feature = "zcash")]
    pub expiry_height_gap: u32,
}
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L281-284)
```rust
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }
```
