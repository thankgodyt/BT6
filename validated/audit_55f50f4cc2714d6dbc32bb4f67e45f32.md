### Title
Hardcoded `GAS_FOR_BURN_CALL` (5 TGas) May Be Insufficient for nBTC `burn` XCC, Causing Stuck Withdrawal State or Unbacked Token Supply - (`contracts/satoshi-bridge/src/nbtc/burn.rs`)

### Summary

The satoshi-bridge forwards exactly `Gas::from_tgas(5)` to the nbtc `burn` cross-contract call in both the withdrawal finalization path and the `safe_mint` rollback path. The `burn` function in the nbtc contract conditionally registers a new account for the relayer and performs a token transfer when `relayer_fee > 0`. These additional storage operations can push gas consumption beyond the hardcoded 5 TGas budget. This is the NEAR analog of Solidity's `.transfer()` forwarding a fixed 2300 gas stipend that became insufficient after EIP-1884 increased SLOAD costs.

### Finding Description

`GAS_FOR_BURN_CALL` is defined as a single constant reused across all `burn` XCC sites: [1](#0-0) 

It is applied in `verify_withdraw_burn_promise` (the primary withdrawal finalization path): [2](#0-1) 

And again in `verify_active_utxo_management_burn_promise`: [3](#0-2) 

And in the `safe_mint_callback` rollback path (fire-and-forget `.detach()`): [4](#0-3) 

The `burn` function in the nbtc contract performs the following operations when `relayer_fee > 0`: [5](#0-4) 

When the relayer (`env::signer_account_id()`) is not yet registered in the nbtc token contract, `internal_register_account` is called followed by `internal_transfer`. Each of these involves multiple `LookupMap` storage reads and writes. Combined with the base function call overhead, Borsh serialization, and `FtBurn` event emission, the total gas consumption can exceed 5 TGas — especially if NEAR protocol storage costs increase (the direct analog to EIP-1884 increasing SLOAD costs).

### Impact Explanation

**Withdrawal path (`verify_withdraw_burn_promise`):** If the `burn` XCC runs out of gas, `verify_withdraw_burn_callback` observes `is_success = false` and calls `to_pending_verify_stage()`: [6](#0-5) 

The pending info reverts to `PendingVerify` stage: [7](#0-6) 

At this point the BTC transaction has already been broadcast and confirmed on-chain, the user's nBTC tokens are held in the bridge's balance (transferred there during `ft_transfer_call`), and the burn cannot complete. If the gas budget is structurally insufficient (e.g., after a NEAR protocol upgrade), every retry of `verify_withdraw` will fail identically, permanently locking the user's nBTC in the bridge with no recovery path for the user.

**`safe_mint_callback` rollback path:** The burn is issued with `.detach()` — there is no callback. If the 5 TGas budget is exhausted, the failure is silently swallowed. The `mint_amount` tokens that were minted to `bridge_id` and returned there by `ft_resolve_transfer` remain in the bridge's balance without being burned, inflating the nBTC supply above the BTC-backed amount.

### Likelihood Explanation

The relayer is a trusted role but is not guaranteed to be pre-registered in the nbtc token contract. Any new relayer account that has never received a relayer fee will trigger the `internal_register_account` branch. Additionally, NEAR protocol upgrades can increase storage operation costs (analogous to EIP-1884), making the fixed 5 TGas budget structurally insufficient over time. The withdrawal path is exercised on every successful withdrawal, making this a regularly reachable code path.

### Recommendation

Replace the single hardcoded `GAS_FOR_BURN_CALL` constant with a budget that accounts for the worst-case `burn` execution (account registration + transfer + event). A value of at least 10–15 TGas is appropriate. For the `safe_mint_callback` rollback path specifically, the `.detach()` burn should be replaced with a chained callback so that a failure can be detected and handled (e.g., by emitting an alert event or storing the unbacked amount for operator recovery), rather than silently leaving unbacked tokens in the bridge balance.

### Proof of Concept

1. A new relayer account (never received a relayer fee, not registered in nbtc) calls `verify_withdraw` for a confirmed BTC transaction.
2. `internal_verify_withdraw_entry` → `internal_verify_withdraw` → light client verification succeeds → `internal_verify_withdraw_callback` transitions state to `PendingBurn` and calls `verify_withdraw_burn_promise`.
3. `verify_withdraw_burn_promise` dispatches `ext_nbtc::burn(...)` with exactly `GAS_FOR_BURN_CALL = 5 TGas` and `relayer_fee > 0`.
4. Inside `nbtc::burn`, `internal_withdraw` + `internal_register_account` + `internal_transfer` + `FtBurn` event emission collectively exhaust the 5 TGas budget; the call fails with gas exhaustion.
5. `verify_withdraw_burn_callback` receives `is_success = false`, calls `to_pending_verify_stage()`.
6. The BTC is already on-chain. The user's nBTC remains locked in the bridge balance. Every subsequent `verify_withdraw` retry by any relayer reproduces the same failure, permanently blocking withdrawal finalization. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-30)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
pub const GAS_FOR_WITHDRAW_BURN_CALL_BACK: Gas = Gas::from_tgas(20);
pub const GAS_FOR_ACTIVE_UTXO_MANAGEMENT_BURN_CALL_BACK: Gas = Gas::from_tgas(20);

impl Contract {
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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L34-41)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                0.into(),
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L149-152)
```rust
        } else {
            self.internal_unwrap_mut_btc_pending_info(&tx_id)
                .to_pending_verify_stage();
        }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L443-451)
```rust
            ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
                .with_static_gas(GAS_FOR_BURN_CALL)
                .burn(
                    env::current_account_id(),
                    mint_amount,
                    relayer_account_id,
                    U128(0),
                )
                .detach();
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L223-247)
```rust
    pub fn to_pending_verify_stage(&mut self) {
        match self.state.borrow_mut() {
            PendingInfoState::WithdrawOriginal(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::WithdrawUserRbf(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::WithdrawCancelRbf(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::ActiveUtxoManagementOriginal(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::ActiveUtxoManagementRbf(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::ActiveUtxoManagementCancelRbf(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
            PendingInfoState::Refund(state) => {
                state.stage = PendingInfoStage::PendingVerify;
            }
        }
    }
```
