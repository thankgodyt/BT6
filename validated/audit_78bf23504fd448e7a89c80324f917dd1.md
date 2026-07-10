### Title
`safe_verify_deposit` Mints Full Deposit Amount Without Deducting Bridge Fee - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary
`internal_safe_verify_deposit` passes the raw `deposit_amount` to `verify_safe_deposit_callback` instead of the fee-reduced `mint_amount`. Any user who calls `safe_verify_deposit` with a valid BTC proof receives the full deposited satoshi value in nBTC, bypassing the deposit bridge fee entirely and inflating the nBTC supply beyond its BTC backing.

### Finding Description

In `internal_verify_deposit` (the relayer path), the deposit fee is correctly computed and subtracted before the callback is scheduled: [1](#0-0) 

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);
...
.verify_deposit_callback(
    recipient_id,
    mint_amount.into(),   // ← correctly reduced
    protocol_fee.into(),
    relayer_fee.into(),
    ...
)
```

In `internal_safe_verify_deposit` (the user-callable path), no fee is computed at all. The raw `deposit_amount` is forwarded directly: [2](#0-1) 

```rust
} else {
    promise.then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
            .verify_safe_deposit_callback(
                recipient_id,
                deposit_amount.into(),   // ← BUG: full amount, fee never deducted
                deposit_msg.msg,
                pending_utxo_info,
            ),
    )
}
```

`verify_safe_deposit_callback` treats its second argument as `mint_amount` and passes it directly to `safe_mint`, which mints it to the recipient with no further deduction: [3](#0-2) 

The `safe_mint_callback` also emits `VerifyDepositDetails` with `protocol_fee: U128(0)` and `relayer_fee: U128(0)`, confirming no fee is collected on this path. [4](#0-3) 

The `BridgeFee::get_fee` function shows the fee is non-trivial — it is `max(amount * fee_rate / 10000, fee_min)`, so every `safe_verify_deposit` call silently skips at least `fee_min` satoshis of fee: [5](#0-4) 

### Impact Explanation

Every call to `safe_verify_deposit` mints `deposit_fee` extra nBTC that has no BTC backing. Over time this permanently inflates the nBTC supply above the BTC held by the bridge, breaking the 1:1 peg. The excess minted tokens are real, transferable nBTC that can be withdrawn or sold. This constitutes unauthorized minting of nBTC and permanent burning below backed supply.

### Likelihood Explanation

`safe_verify_deposit` is a public, permissionless entry point — any user who has sent BTC to a deposit address can call it by attaching the required NEAR storage deposit. The entry point is explicitly designed for users to self-serve their deposits without waiting for a relayer. The fee bypass requires no special knowledge: the user simply calls `safe_verify_deposit` instead of waiting for a relayer to call `verify_deposit`. Every such call produces excess nBTC equal to the bridge fee. [6](#0-5) 

### Recommendation

Apply the same fee-deduction logic used in `internal_verify_deposit` to `internal_safe_verify_deposit`:

```rust
} else {
    let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
    let mint_amount = deposit_amount - deposit_fee;
    promise.then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
            .verify_safe_deposit_callback(
                recipient_id,
                mint_amount.into(),   // ← use fee-reduced amount
                deposit_msg.msg,
                pending_utxo_info,
            ),
    )
}
```

The `verify_safe_deposit_callback` and `safe_mint_callback` should also be updated to accept and emit `protocol_fee` and `relayer_fee` fields so the fee is properly distributed and accounted for, mirroring the `verify_deposit_callback` path.

### Proof of Concept

1. User sends 500,000 satoshis to their deposit address on Bitcoin.
2. User calls `safe_verify_deposit` with the valid Merkle proof (attaching the required NEAR storage deposit).
3. `internal_safe_verify_deposit_entry` decodes the transaction, reads `deposit_amount = 500_000`, and calls `internal_safe_verify_deposit`.
4. `internal_safe_verify_deposit` schedules `verify_safe_deposit_callback` with `deposit_amount = 500_000` — no fee is subtracted.
5. After the Light Client confirms inclusion, `verify_safe_deposit_callback` calls `safe_mint(recipient, 500_000, ...)`.
6. The user receives 500,000 nBTC. With a `fee_min = 50_000` configuration, the correct amount would have been 450,000 nBTC. The user received 50,000 nBTC for free, unbacked by BTC.
7. The bridge's nBTC supply now exceeds its BTC holdings by 50,000 satoshis per such deposit. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L52-70)
```rust
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
            let (protocol_fee, relayer_fee) = config
                .deposit_bridge_fee
                .get_protocol_and_relayer_fee(deposit_fee);

            let post_actions = self.check_deposit_msg(deposit_msg, mint_amount);
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_deposit_callback(
                        recipient_id,
                        mint_amount.into(),
                        protocol_fee.into(),
                        relayer_fee.into(),
                        pending_utxo_info,
                        post_actions,
                    ),
            )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L74-115)
```rust
    pub(crate) fn internal_safe_verify_deposit(
        &mut self,
        deposit_amount: u128,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
        coinbase_proof: Option<(String, Vec<String>)>,
        pending_utxo_info: PendingUTXOInfo,
        recipient_id: AccountId,
        deposit_msg: SafeDepositMsg,
    ) -> Promise {
        let config = self.internal_config();
        let confirmations = self.get_confirmations(config, deposit_amount);
        let promise = self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            pending_utxo_info.tx_id.clone(),
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            confirmations,
        );

        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_safe_deposit_callback(
                        recipient_id,
                        deposit_amount.into(),
                        deposit_msg.msg,
                        pending_utxo_info,
                    ),
            )
        }
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L171-184)
```rust
    pub(crate) fn internal_safe_verify_deposit_entry(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
        coinbase_proof: Option<(String, Vec<String>)>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L387-419)
```rust
    pub fn verify_safe_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        msg: String,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );

        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L458-466)
```rust
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee: U128(0),
            relayer_account_id: env::signer_account_id(),
            relayer_fee: U128(0),
            success: is_success,
        }
        .emit();
```

**File:** contracts/satoshi-bridge/src/config.rs (L30-35)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }
```
