### Title
Insufficient Gas Stipend for nBTC Burn Cross-Contract Call May Permanently Strand Withdrawals - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary
The satoshi-bridge allocates only `5 TGas` to the `burn` cross-contract call on the nbtc contract. When a withdrawal includes a non-zero relayer fee and the relayer account is not yet registered in the nbtc contract, the burn function must perform additional storage writes (account registration + token transfer). This extra work can push gas consumption above the 5 TGas ceiling, causing the burn call to fail. Because the failure handler puts the withdrawal back into `PendingVerify` stage rather than aborting it, and because every subsequent `verify_withdraw` attempt re-issues the same under-gassed burn call, the withdrawal becomes permanently stuck without operator intervention.

### Finding Description

`GAS_FOR_BURN_CALL` is defined as 5 TGas and is used in every path that calls `burn` on the nbtc contract: [1](#0-0) 

It is applied in `verify_withdraw_burn_promise` (the normal withdrawal finalization path): [2](#0-1) 

And in `verify_active_utxo_management_burn_promise`: [3](#0-2) 

The nbtc `burn` function has two execution paths depending on `relayer_fee`: [4](#0-3) 

**Simple path** (`relayer_fee == 0`): one `internal_withdraw` + one event emit. This is cheap and 5 TGas is likely sufficient.

**Complex path** (`relayer_fee > 0`, relayer not yet registered): `internal_withdraw` + `accounts.get` check + `internal_register_account` (new storage write) + `internal_transfer` (two reads + two writes) + event emit. The base NEAR cross-contract call overhead alone is ~2.3 TGas; the additional storage operations and Wasm execution for this path push total consumption to approximately 4–5+ TGas, making failure under the 5 TGas ceiling realistic.

For comparison, the bridge allocates **20 TGas** for a plain `ft_transfer` call — an operation of comparable or lesser complexity: [5](#0-4) 

When the burn call fails, `verify_withdraw_burn_callback` receives a failed promise result and calls `to_pending_verify_stage()`: [6](#0-5) 

This re-queues the withdrawal for another `verify_withdraw` call. But every subsequent call will again issue `burn` with the same 5 TGas, producing the same failure in an infinite loop. The user's BTC has already been sent on-chain; the nBTC has not been burned; the bridge state is stuck.

### Impact Explanation

A withdrawal that triggers the complex burn path (non-zero relayer fee, unregistered relayer) can be permanently frozen. The user's nBTC remains locked in the bridge's pending state, and the corresponding BTC output on Bitcoin is already signed and broadcast. No user-callable function can break the loop; only privileged operator intervention (if such a path exists) could resolve it. This matches the **Medium** impact class: broken callback rollback / stuck bridge state requiring operator intervention.

### Likelihood Explanation

Every normal withdrawal that pays a relayer fee is affected when the relayer submitting `verify_withdraw` has not previously registered in the nbtc contract. New relayers, or relayers rotating accounts, satisfy this condition. The condition is reachable by any public relayer submitting a valid withdrawal proof.

### Recommendation

Increase `GAS_FOR_BURN_CALL` to at least **20 TGas**, consistent with the gas already allocated for `ft_transfer` operations of comparable complexity. Consider also adding a dynamic gas check (similar to the `handle_post_action` guard in nbtc) so that the burn call fails fast with a clear error rather than silently running out of gas mid-execution. [7](#0-6) 

### Proof of Concept

1. User initiates a withdrawal via `ft_transfer_call` with a valid `WithdrawMsg`. The bridge creates a `BTCPendingInfo` with `withdraw_fee > 0`.
2. The bridge constructs and signs the Bitcoin PSBT via MPC. The signed transaction is broadcast.
3. A relayer (whose account is **not** registered in the nbtc contract) calls `verify_withdraw` with the Bitcoin inclusion proof.
4. `internal_verify_withdraw_callback` succeeds, transitions state to `PendingBurn`, and calls `verify_withdraw_burn_promise`.
5. `verify_withdraw_burn_promise` dispatches `ext_nbtc::burn(...)` with `GAS_FOR_BURN_CALL = 5 TGas` and `relayer_fee > 0`.
6. Inside `burn`, the code reaches `internal_register_account` + `internal_transfer` for the unregistered relayer. Gas is exhausted; the call fails.
7. `verify_withdraw_burn_callback` sees `is_promise_success() == false` and calls `to_pending_verify_stage()`.
8. Steps 3–7 repeat indefinitely. The withdrawal is permanently stuck; the user's nBTC is locked in the bridge and cannot be recovered without operator intervention. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-6)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L11-30)
```rust
    pub fn verify_withdraw_burn_promise(&self, tx_id: String) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        let config = self.internal_config();
        let (protocol_fee, relayer_fee) = config
            .withdraw_bridge_fee
            .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
                    .verify_withdraw_burn_callback(tx_id, protocol_fee.into(), relayer_fee.into()),
            )
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L34-46)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                0.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_ACTIVE_UTXO_MANAGEMENT_BURN_CALL_BACK)
                    .verify_active_utxo_management_burn_callback(tx_id),
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L149-152)
```rust
        } else {
            self.internal_unwrap_mut_btc_pending_info(&tx_id)
                .to_pending_verify_stage();
        }
```

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

**File:** contracts/nbtc/src/lib.rs (L393-396)
```rust
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L7-8)
```rust
pub const GAS_FOR_TOKEN_TRANSFER: Gas = Gas::from_tgas(20);
pub const GAS_FOR_AFTER_TOKEN_TRANSFER: Gas = Gas::from_tgas(10);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L71-82)
```rust
    pub fn internal_verify_withdraw_callback(&mut self, tx_id: String) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        self.internal_unwrap_btc_pending_info(&tx_id)
            .assert_pending_verify();
        self.internal_unwrap_mut_btc_pending_info(&tx_id)
            .to_pending_burn_stage();
        self.verify_withdraw_burn_promise(tx_id).into()
    }
```
