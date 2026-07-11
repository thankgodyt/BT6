### Title
`env::signer_account_id()` (tx.origin Analog) Used for Relayer Fee Distribution Enables Fee Capture via Proxy Contracts — (File: `contracts/satoshi-bridge/src/nbtc/mint.rs`, `contracts/satoshi-bridge/src/nbtc/burn.rs`)

---

### Summary

The bridge uses `env::signer_account_id()` — NEAR Protocol's direct analog to Ethereum's `tx.origin` — to identify the relayer for fee distribution in both the deposit and withdrawal flows. When a trusted proxy contract submits a deposit or withdrawal proof, the relayer fee is incorrectly attributed to the original transaction signer (the end user) rather than the proxy contract (the actual relayer). This allows any user to capture relayer fees by routing their transactions through a whitelisted proxy contract, rendering the relayer incentivization strategy ineffective.

---

### Finding Description

In `internal_mint_promise`, `env::signer_account_id()` is passed as the `relayer_account_id` to `nbtc.mint()`: [1](#0-0) 

In `verify_withdraw_burn_promise`, `env::signer_account_id()` is passed as the `relayer_account_id` to `nbtc.burn()`, which then transfers the `relayer_fee` to that account: [2](#0-1) 

In NEAR Protocol, `env::signer_account_id()` returns the account that **originally signed the transaction** (equivalent to `tx.origin` in Ethereum), while `env::predecessor_account_id()` returns the **immediate caller** (equivalent to `msg.sender`). When a proxy contract calls `verify_deposit` or `verify_withdraw`, `signer_account_id()` resolves to the user who called the proxy — not the proxy contract itself.

The codebase explicitly acknowledges and supports proxy protocols. The `get_confirmations` function correctly uses `predecessor_account_id()` for the whitelist check, with the comment: [3](#0-2) 

This confirms the design intent: proxy protocols are expected to call `verify_deposit`/`verify_withdraw` as `predecessor`, while the original user is the `signer`. However, the fee distribution uses `signer_account_id()`, creating a direct inconsistency: the proxy contract does the work and satisfies the whitelist check (getting the reduced-confirmation benefit), but the relayer fee flows to the user (original signer) instead.

The same pattern appears in `verify_active_utxo_management_burn_promise`: [4](#0-3) 

Additionally, `safe_mint_callback` uses `env::signer_account_id()` for the storage deposit refund on failure, meaning a proxy contract that attaches the required NEAR for `safe_verify_deposit` loses those funds to the original signer if the mint fails: [5](#0-4) 

The `nbtc.mint()` function distributes the `relayer_fee` directly to the `relayer_account_id` parameter: [6](#0-5) 

---

### Impact Explanation

Any user who routes a `verify_deposit` or `verify_withdraw` call through a whitelisted proxy contract (e.g., Omni Bridge or any future integration) will receive the relayer fee instead of the proxy contract. This:

1. **Renders the relayer incentivization strategy ineffective**: users earn fees without operating relayer infrastructure.
2. **Removes the financial incentive for proxy protocols** to act as trusted relayers, since they receive no fee for their work.
3. **Allows fee capture without privilege**: no special role is required — only access to a publicly callable trusted proxy contract.

This maps to the **Medium** allowed impact: *Bypass of bridge limits or policies*.

---

### Likelihood Explanation

The design explicitly supports proxy protocols calling `verify_deposit` and `verify_withdraw` (evidenced by the `predecessor_account_id` comment in `get_confirmations`). Any user aware of a whitelisted proxy contract can exploit this. The attack requires no special privileges, no leaked keys, and no operator cooperation. As the bridge ecosystem grows and more integrations are added, the number of exploitable proxy entry points increases.

---

### Recommendation

Replace `env::signer_account_id()` with `env::predecessor_account_id()` for relayer fee attribution in `internal_mint_promise` and `verify_withdraw_burn_promise`. This ensures the fee is paid to the actual immediate caller (the relayer or proxy contract), not the original transaction signer. The same fix should be applied to `safe_mint_callback`'s storage deposit refund.

---

### Proof of Concept

1. A proxy contract `proxy.near` is added to the bridge's `relayer_white_list` (trusted relayer).
2. User `alice.near` calls `proxy.near::submit_deposit_proof(tx_bytes, vout, proof)`.
3. `proxy.near` calls `bridge.verify_deposit(deposit_msg, tx_bytes, vout, ...)`.
4. Inside `internal_mint_promise`, `env::signer_account_id()` = `alice.near`, `env::predecessor_account_id()` = `proxy.near`.
5. `nbtc.mint(recipient, mint_amount, protocol_fee, alice.near, relayer_fee, ...)` is called.
6. `alice.near` receives the `relayer_fee` in nBTC — despite doing no relayer work.
7. `proxy.near` receives nothing, despite being the whitelisted relayer that submitted the proof and satisfied the confirmation requirement.
8. Any user can repeat this for every deposit/withdrawal, systematically capturing all relayer fees from any whitelisted proxy integration.

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L19-28)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .mint(
                recipient_id.clone(),
                mint_amount,
                protocol_fee,
                env::signer_account_id(),
                relayer_fee,
                post_actions,
            )
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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L32-47)
```rust
    pub fn verify_active_utxo_management_burn_promise(&self, tx_id: String) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
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
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L321-332)
```rust
    pub fn get_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
        if self
            .data()
            .relayer_white_list
            // Use predecessor_account_id to support both users and proxy protocols.
            .contains(&env::predecessor_account_id())
        {
            config.get_confirmations(satoshi_amount)
        } else {
            config.get_confirmations(satoshi_amount) + u64::from(config.confirmations_delta)
        }
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L429-455)
```rust
        let relayer_account_id = env::signer_account_id();

        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);

            ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
                .with_static_gas(GAS_FOR_BURN_CALL)
                .burn(
                    env::current_account_id(),
                    mint_amount,
                    relayer_account_id,
                    U128(0),
                )
                .detach();

            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
```

**File:** contracts/nbtc/src/lib.rs (L140-142)
```rust
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
```
