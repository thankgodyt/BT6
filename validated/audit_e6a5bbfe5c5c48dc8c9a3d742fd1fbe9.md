### Title
Hardcoded Zcash Network-Upgrade Activation Heights Will Produce Invalid Transactions After Any Future Zcash Network Upgrade - (File: contracts/satoshi-bridge/src/network.rs)

### Summary

`BranchIdUpdateBlockHeight` in `network.rs` hard-codes the block heights at which Zcash consensus branches NU6.1 and NU6.2 activate. These values live in compiled source code, not in the updatable `Config` struct. When Zcash activates a future network upgrade (NU7 or later), `get_branch_id()` will permanently return `BranchId::Nu6_2` for every block height, causing every withdrawal and refund transaction to be constructed with the wrong consensus branch ID. Zcash nodes reject transactions whose `branch_id` does not match the current consensus branch, so all bridge-constructed Zcash transactions will be invalid and unbroadcastable after the next upgrade.

### Finding Description

`BranchIdUpdateBlockHeight::new()` returns a struct whose two fields are literal integer constants baked into the match arms:

```rust
// contracts/satoshi-bridge/src/network.rs  lines 36-49
impl BranchIdUpdateBlockHeight {
    pub fn new(chain: &Chain) -> Self {
        match chain {
            Chain::ZcashMainnet => Self {
                nu6_1_update: 3146400,
                nu6_2_update: 3364600,
            },
            Chain::ZcashTestnet => Self {
                nu6_1_update: 3536500,
                nu6_2_update: 4052000,
            },
            _ => unreachable!(),
        }
    }
}
```

`get_branch_id()` uses these constants and has no branch for any upgrade beyond NU6.2:

```rust
// lines 53-65
pub fn get_branch_id(&self, block_height: u32) -> BranchId {
    let block_height_update = BranchIdUpdateBlockHeight::new(self);
    if block_height_update.nu6_2_update != 0
        && block_height >= block_height_update.nu6_2_update
    {
        return BranchId::Nu6_2;
    }
    if block_height_update.nu6_1_update != 0
        && block_height >= block_height_update.nu6_1_update
    {
        return BranchId::Nu6_1;
    }
    BranchId::Nu6
}
```

`get_branch_id()` is called at every withdrawal and refund transaction construction point:

- `PsbtWrapper::new()` — called from `ft_on_transfer_callback` (withdrawal) and `active_utxo_management_callback`
- `PsbtWrapper::from_original_psbt()` — called from RBF paths
- `execute_refund_callback` — called from the refund flow

The `branch_id` is embedded in the serialized PSBT stored on-chain and is used when building the final Zcash transaction via `get_zcash_tx()` → `TransactionData::from_parts(... self.branch_id ...)`.

Additionally, `PsbtWrapper::deserialize()` has a hardcoded match that panics on any unknown branch ID byte:

```rust
match branch_id_u8 {
    7 => BranchId::Nu6,
    8 => BranchId::Nu6_1,
    9 => BranchId::Nu6_2,
    _ => env::panic_str("ERR_INVALID_PSBT: unsupported branch_id"),
}
```

Neither `BranchIdUpdateBlockHeight` nor the branch-ID byte mapping is part of the `Config` struct and therefore cannot be updated via `update_config`. A full contract upgrade is required.

### Impact Explanation

After a future Zcash network upgrade (NU7+) activates:

1. Every call to `get_branch_id()` returns `BranchId::Nu6_2` regardless of the actual current height.
2. Every withdrawal and refund transaction is constructed with `consensus_branch_id = Nu6_2`.
3. Zcash full nodes enforce that `consensus_branch_id` matches the active branch; transactions with a stale branch ID are unconditionally rejected at the mempool level.
4. No withdrawal or refund transaction can ever be confirmed on the Zcash network.
5. Users who have initiated withdrawals have their nZEC held by the bridge in a permanently pending state. Without operator intervention (contract upgrade + re-execution), those funds are stuck indefinitely.
6. Any existing pending PSBTs that were serialized before the upgrade and are deserialized after a contract upgrade that adds a new branch-ID byte will panic in `deserialize()`, bricking those pending transactions entirely.

This matches the **Critical** allowed impact: "Significant loss, theft, destruction, or permanent locking of user or protocol funds" and **Medium**: "stuck bridge state requiring operator intervention."

### Likelihood Explanation

Zcash has a well-documented history of regular network upgrades: NU5 (Orchard), NU6, NU6.1, NU6.2 have all activated on both mainnet and testnet within the past two years. The Zcash protocol roadmap explicitly plans further upgrades. The external report's reference case (Optimism Bedrock) is directly analogous: a planned, announced protocol-level change that invalidates a hardcoded parameter. The probability of at least one future Zcash upgrade during the bridge's operational lifetime is near-certain.

### Recommendation

Move the network-upgrade activation heights into the `Config` struct so they can be updated via `update_config` without a contract redeployment:

```rust
pub struct Config {
    // ... existing fields ...
    #[cfg(feature = "zcash")]
    pub nu6_1_activation_height: u32,
    #[cfg(feature = "zcash")]
    pub nu6_2_activation_height: u32,
}
```

Pass these values into `get_branch_id()` instead of constructing `BranchIdUpdateBlockHeight` from hardcoded constants. Similarly, make the branch-ID byte mapping in `PsbtWrapper::deserialize()` extensible (e.g., a config-driven lookup table) rather than a hardcoded match that panics on unknown values. A governance timelock (analogous to the freeze period recommended in the external report) should gate any change to activation heights so that users can exit before a potentially disruptive reconfiguration takes effect.

### Proof of Concept

**State:** Bridge deployed on Zcash mainnet. Zcash activates NU7 at block height `H_NU7`.

1. At block `H_NU7 + 1`, user Alice calls `ft_transfer_call` on the nZEC contract to initiate a withdrawal of 1 ZEC to her transparent address.
2. The bridge calls `get_last_block_height_promise()`, receives `H_NU7 + 1`, and passes it to `ft_on_transfer_callback`.
3. Inside `ft_on_transfer_callback`, `get_expiry_height()` calls `self.get_config().expiry_height_gap` and `PsbtWrapper::new()` calls `get_branch_id(H_NU7 + 1, config)`.
4. `get_branch_id` evaluates: `H_NU7 + 1 >= nu6_2_update (3364600)` → `true` → returns `BranchId::Nu6_2`. NU7 is not handled; the function has no branch for it.
5. The PSBT is stored on-chain with `branch_id = Nu6_2`.
6. MPC signs the transaction. The signed transaction is broadcast to the Zcash network.
7. Every Zcash node rejects the transaction: `consensus_branch_id` field is `Nu6_2` but the active branch is `Nu7`. The transaction is permanently invalid.
8. Alice's nZEC remains locked in the bridge's pending state. No withdrawal can succeed until the bridge is upgraded and the transaction is re-executed with the correct branch ID. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/network.rs (L36-50)
```rust
impl BranchIdUpdateBlockHeight {
    pub fn new(chain: &Chain) -> Self {
        match chain {
            Chain::ZcashMainnet => Self {
                nu6_1_update: 3146400,
                nu6_2_update: 3364600,
            },
            Chain::ZcashTestnet => Self {
                nu6_1_update: 3536500,
                nu6_2_update: 4052000,
            },
            _ => unreachable!(),
        }
    }
}
```

**File:** contracts/satoshi-bridge/src/network.rs (L52-66)
```rust
    #[cfg(feature = "zcash")]
    pub fn get_branch_id(&self, block_height: u32) -> BranchId {
        let block_height_update = BranchIdUpdateBlockHeight::new(self);
        if block_height_update.nu6_2_update != 0 && block_height >= block_height_update.nu6_2_update
        {
            return BranchId::Nu6_2;
        }
        if block_height_update.nu6_1_update != 0 && block_height >= block_height_update.nu6_1_update
        {
            return BranchId::Nu6_1;
        }

        BranchId::Nu6
    }
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L85-93)
```rust
        Self {
            branch_id: get_branch_id(current_height, config),
            expiry_height,
            vout,
            vin,
            inputs_utxo: inputs,
            orchard,
            recipient_address,
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L286-297)
```rust
        let branch_id = if version >= 2 {
            let branch_id_u8 = read_u8(&mut rdr)
                .unwrap_or_else(|_| env::panic_str("ERR_INVALID_PSBT: failed to read branch_id"));
            match branch_id_u8 {
                7 => BranchId::Nu6,
                8 => BranchId::Nu6_1,
                9 => BranchId::Nu6_2,
                _ => env::panic_str("ERR_INVALID_PSBT: unsupported branch_id"),
            }
        } else {
            BranchId::Nu6_1
        };
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L119-137)
```rust
        #[callback_unwrap] last_block_height: u32,
    ) -> U128 {
        let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        let psbt = PsbtWrapper::new(
            input,
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(target_btc_address.clone()),
            self.internal_config(),
        );

        self.create_btc_pending_info(sender_id, amount.0, target_btc_address, psbt, max_gas_fee);

        U128(0)
    }
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
