### Title
Stale `last_block_height` from BTC Light Client Used Without Freshness Validation Causes Zcash Withdrawal Transactions to Be Constructed with Expired Expiry Heights — (File: `contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs`)

### Summary

The Zcash withdrawal path fetches the current block height from the BTC light client via `get_last_block_height()` and uses it to compute the `expiry_height` field of the Zcash transaction. No staleness check is performed on the returned value. If the light client is behind the actual Zcash chain tip by more than `expiry_height_gap` blocks, every Zcash transaction constructed during that window will carry an expiry height that has already passed, making the transaction immediately invalid on the Zcash network. The user's nZEC tokens are consumed by the bridge (the callback returns `U128(0)`), the MPC signs the expired transaction, but the transaction can never confirm, leaving user funds stuck in the bridge pending state until operator intervention.

### Finding Description

**Entry path:**

A normal user initiates a Zcash withdrawal by calling `ft_transfer_call` on the nZEC token contract. This triggers `ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific`, which issues a cross-contract call to `get_last_block_height_promise()`: [1](#0-0) 

`get_last_block_height_promise()` simply forwards the call to the configured light client with no freshness constraint: [2](#0-1) 

The returned value is passed directly into `ft_on_transfer_callback` as `last_block_height`: [3](#0-2) 

`get_expiry_height` validates the expiry height only relative to the stale `last_block_height`, not relative to the actual chain tip: [4](#0-3) 

If the light client's stored height is `S` blocks behind the real chain tip `T`, and `expiry_height_gap` is `G`, the constructed transaction carries `expiry_height = S + G`. On the Zcash network the current height is `T`, so the transaction is valid only if `S + G > T`, i.e., the staleness `T - S < G`. Once the light client falls behind by more than `G` blocks, every withdrawal transaction is born expired.

The same stale-height path exists in `active_utxo_management_callback`: [5](#0-4) 

**Why the bridge code is the necessary vulnerable step:**

The bridge code is responsible for validating the data it receives from the light client before using it for critical transaction construction. There is no staleness guard — no maximum age check, no comparison against `env::block_timestamp()`, and no minimum acceptable height. The `get_expiry_height` validation is entirely self-referential: it only checks that the user-supplied value is within `[stale + gap, stale + 2*gap]`, which is meaningless if `stale` itself is far behind the real tip.

### Impact Explanation

When the light client is stale by more than `expiry_height_gap` blocks:

1. `ft_on_transfer_callback` returns `U128(0)` — the user's nZEC tokens are transferred to and held by the bridge contract.
2. A `BTCPendingInfo` is created with the expired PSBT.
3. The MPC signs the expired transaction (the signature is cryptographically valid).
4. The signed transaction is broadcast to the Zcash network and immediately rejected because `expiry_height < current_height`.
5. The user's nZEC is stuck in the bridge's pending state; the withdrawal can never complete.
6. Recovery requires DAO/Operator to call `cancel_withdraw`, which routes the nZEC through `lost_found` for the user to reclaim.

This matches the **Medium** impact category: stuck bridge state requiring operator intervention, with temporary locking of bridged user funds.

### Likelihood Explanation

The BTC light client is an external contract that must be actively updated by relayers. Zcash produces a block roughly every 75 seconds. If `expiry_height_gap` is configured at a small value (e.g., 40 blocks ≈ 50 minutes), any light client lag exceeding that window — due to relayer downtime, network congestion, or a slow block period — triggers the issue for every Zcash withdrawal initiated during the lag. This is an operational condition that can arise without any attacker action; it is directly analogous to the external report's finding that some Chainlink oracles reported stale data for a full day.

### Recommendation

Add a staleness guard in `ft_on_transfer_callback` (and `active_utxo_management_callback`) before using `last_block_height`. For example, store the NEAR block timestamp at which the light client height was last updated and reject the withdrawal if the age exceeds a configured threshold. Alternatively, require that `last_block_height` is within a configurable tolerance of a known-recent anchor (e.g., the height recorded at the last successful deposit verification). At minimum, document the operational requirement that the light client must be kept within `expiry_height_gap` blocks of the chain tip, and add a circuit-breaker that pauses Zcash withdrawals when the light client is detected as stale.

### Proof of Concept

1. Light client is at height `S = 1000`; actual Zcash chain tip is `T = 1050`; `expiry_height_gap = G = 40`.
2. User calls `ft_transfer_call` on nZEC, triggering the withdrawal flow.
3. `get_last_block_height()` returns `1000`.
4. `get_expiry_height` computes `expiry_height = 1000 + 40 = 1040`.
5. Validation passes: `1040 >= 1000 + 40` and `1040 <= 1000 + 80`. ✓
6. PSBT is built with `expiry_height = 1040`; `create_btc_pending_info` stores it; callback returns `U128(0)` — user's nZEC is consumed.
7. MPC signs the transaction.
8. Signed transaction is broadcast to Zcash. The network's current height is `1050 > 1040`, so the transaction is expired and rejected.
9. User's nZEC is permanently stuck in the bridge pending state until a DAO/Operator calls `cancel_withdraw`. [4](#0-3) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L119-136)
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
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L141-163)
```rust
    pub fn active_utxo_management_callback(
        &mut self,
        account_id: AccountId,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        #[callback_unwrap] last_block_height: u32,
    ) {
        let expiry_height = last_block_height + self.get_config().expiry_height_gap;

        // For active UTXO management, we don't validate orchard recipient/amount
        // as this is internal bridge operations, not user withdrawals
        let psbt = PsbtWrapper::new(
            input,
            output,
            None,
            expiry_height,
            last_block_height,
            None,
            self.internal_config(),
        );

        self.create_active_utxo_management_pending_info(account_id, psbt);
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L167-190)
```rust
    pub(crate) fn get_expiry_height(
        &self,
        chain_specific_data: &Option<ChainSpecificData>,
        last_block_height: u32,
    ) -> u32 {
        let expiry_height = if let Some(chain_specific_data) = chain_specific_data {
            chain_specific_data.expiry_height
        } else {
            last_block_height + self.get_config().expiry_height_gap
        };

        require!(
            expiry_height >= last_block_height + self.get_config().expiry_height_gap
                && expiry_height <= last_block_height + 2 * self.get_config().expiry_height_gap,
            format!(
                "Invalid expiry height: {}. Expected value between {} and {}.",
                expiry_height,
                last_block_height + self.get_config().expiry_height_gap,
                last_block_height + 2 * self.get_config().expiry_height_gap
            )
        );

        expiry_height
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L231-245)
```rust
        PromiseOrValue::Promise(
            self.get_last_block_height_promise().then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_FT_ON_TRANSFER_CALL_BACK)
                    .ft_on_transfer_callback(
                        sender_id,
                        amount.into(),
                        target_btc_address,
                        input,
                        output,
                        max_gas_fee,
                        chain_specific_data,
                    ),
            ),
        )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/mod.rs (L201-206)
```rust
    pub fn get_last_block_height_promise(&self) -> Promise {
        let config = self.internal_config();
        ext_btc_light_client::ext(config.btc_light_client_account_id.clone())
            .with_static_gas(GAS_FOR_GET_LAST_BLOCK_HEIGHT)
            .get_last_block_height()
    }
```
