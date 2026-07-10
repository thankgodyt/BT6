### Title
Deposit Bridge Fee Not Applied in Safe Deposit Flow, Allowing Full Amount Minting Without Fee Deduction - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
The `internal_safe_verify_deposit` function mints the full raw `deposit_amount` to the recipient without deducting the configured `deposit_bridge_fee`, while the standard `internal_verify_deposit` path correctly computes and deducts the fee before minting. Any user who triggers the safe-deposit flow receives more nBTC than they should, and the protocol and relayer collect zero fee revenue for those deposits.

### Finding Description
The bridge has two deposit verification paths. The standard path in `internal_verify_deposit` correctly applies the fee:

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);
// → verify_deposit_callback(recipient, mint_amount, protocol_fee, relayer_fee, ...)
``` [1](#0-0) 

The safe-deposit path in `internal_safe_verify_deposit` skips all of that and passes the raw `deposit_amount` directly as the mint amount:

```rust
promise.then(
    Self::ext(env::current_account_id())
        .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
        .verify_safe_deposit_callback(
            recipient_id,
            deposit_amount.into(),   // ← full amount, no fee deducted
            deposit_msg.msg,
            pending_utxo_info,
        ),
)
``` [2](#0-1) 

`verify_safe_deposit_callback` then calls `safe_mint` with that uncorrected amount, so the recipient receives `deposit_amount` nBTC instead of `deposit_amount - deposit_bridge_fee`: [3](#0-2) 

The `safe_mint` function in the nBTC contract mints to the bridge balance and transfers to the recipient without any fee logic of its own: [4](#0-3) 

The `deposit_bridge_fee` configuration field exists and is fully functional — it is simply never consulted in the safe-deposit code path. [5](#0-4) 

### Impact Explanation
Every safe-deposit user receives the full `deposit_amount` in nBTC with zero fee deducted. The protocol collects no `protocol_fee` and the relayer collects no `relayer_fee` for these deposits. The `safe_mint_callback` confirms this by emitting `protocol_fee: U128(0)` and `relayer_fee: U128(0)` unconditionally: [6](#0-5) 

This is a bypass of the bridge's fee policy. The total nBTC minted per deposit equals the full BTC deposited (so the 1:1 BTC-backing invariant is not broken), but the fee revenue that should accrue to the protocol and relayer is permanently lost for every safe-deposit transaction. This matches the **Medium** allowed impact: *Bypass of bridge limits or policies*.

### Likelihood Explanation
The safe-deposit entry point (`internal_safe_verify_deposit_entry`) is a production code path reachable by any unprivileged user who submits a `DepositMsg` with a `safe_deposit` field set. No privileged role is required. The fee bypass is automatic and unconditional — every invocation of this path skips the fee. [7](#0-6) 

### Recommendation
Apply the same fee deduction logic used in `internal_verify_deposit` inside `internal_safe_verify_deposit` before scheduling `verify_safe_deposit_callback`:

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
// pass mint_amount (not deposit_amount) to verify_safe_deposit_callback
```

`verify_safe_deposit_callback` should also accept and forward `protocol_fee` and `relayer_fee` so that `safe_mint_callback` can credit them to `acc_collected_protocol_fee` / `cur_available_protocol_fee` and to the relayer, mirroring the standard `mint_callback` logic.

### Proof of Concept
1. User sends 1 000 000 satoshi to the safe-deposit address.
2. User calls `safe_verify_deposit` with a valid SPV proof.
3. `internal_safe_verify_deposit` schedules `verify_safe_deposit_callback` with `mint_amount = 1_000_000` (no fee deducted).
4. Suppose `deposit_bridge_fee` has `fee_min = 0` and `fee_rate = 30` (0.3 %). The standard path would mint `997 000` to the user and `3 000` to protocol/relayer.
5. Instead, `safe_mint` mints `1 000 000` nBTC to the user.
6. Protocol and relayer receive `0` fee. The user has received `3 000` extra nBTC at the protocol's expense.
7. Repeating this for every deposit drains all expected fee revenue from the bridge.

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L104-114)
```rust
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
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L171-237)
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

        let path = get_deposit_path(&deposit_msg);
        let safe_deposit_msg = deposit_msg
            .safe_deposit
            .unwrap_or_else(|| env::panic_str("safe_deposit is required in safe_verify_deposit"));

        let transaction = WrappedTransaction::decode(&tx_bytes, &self.internal_config().chain)
            .expect("Deserialization tx_bytes failed");
        let deposit_amount = transaction.output()[vout].value.to_sat().into();
        require!(deposit_amount > 0, "Invalid deposit_amount");
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_address_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_address_script_pubkey == transaction.output()[vout].script_pubkey,
            "Invalid deposit tx_bytes"
        );

        let tx_bytes = if tx_bytes.len() > 10000 {
            env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
            vec![0u8; 300]
        } else {
            tx_bytes
        };

        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id.clone(),
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        self.internal_safe_verify_deposit(
            deposit_amount,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            PendingUTXOInfo {
                tx_id,
                utxo_storage_key,
                utxo,
            },
            deposit_msg.recipient_id,
            safe_deposit_msg,
        )
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L409-418)
```rust
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

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L30-41)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }

    pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
        let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
        let relayer_fee = fee_amount - protocol_fee;
        (protocol_fee, relayer_fee)
    }
```
