### Title
`swap_migrated_token` Mints Incorrect Amounts When Old and New Tokens Have Different Decimals — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`swap_migrated_token` burns a raw `amount` of `old_token` and mints the identical raw `amount` of `new_token` with no decimal normalization. `migrate_deployed_token` imposes no constraint that the two tokens share the same decimal precision. When a migration pairs tokens with different decimals, every user who swaps receives a wildly incorrect number of new tokens.

---

### Finding Description

`migrate_deployed_token` is a DAO-gated function that rebinds a NEAR token AccountId from `old_token` to `new_token` while keeping the same foreign-chain `origin_address`: [1](#0-0) 

It updates `deployed_tokens`, `deployed_tokens_v2`, `token_id_to_address`, `token_address_to_id`, and `migrated_tokens`, but it **never reads or validates the decimal precision of either token**. The `token_decimals` map (keyed by `OmniAddress`, i.e. the foreign-chain address) is left untouched and is never consulted during the swap.

After migration, any holder of `old_token` can trigger `swap_migrated_token` by calling `ft_transfer_call` on `old_token` with the message `SwapMigratedToken`. The bridge handler dispatches to: [2](#0-1) 

The function burns `amount` of `old_token` and mints the **same raw integer `amount`** of `new_token`. No normalization, no scaling, no decimal check. If `old_token` carries 24 decimals and `new_token` carries 18 decimals, a user who sends `1e24` (= 1.0 old token) receives `1e24` new tokens (= 1,000,000 new tokens at 18 decimals). The inverse is equally harmful: a user migrating from 6 to 24 decimals loses `1e18` factor of value.

The entry point is fully unprivileged once the migration is registered: [3](#0-2) 

---

### Impact Explanation

**Critical — balance manipulation / decimal normalization abuse causing loss or unauthorized gain of bridged funds.**

- If `new_token` has **more** decimals than `old_token`: every swapper receives orders-of-magnitude more tokens than they deposited, draining the bridge's minting authority and inflating the new token's supply beyond what was ever locked on the origin chain.
- If `new_token` has **fewer** decimals: every swapper loses the corresponding factor of value with no recourse, permanently destroying user funds.

Both directions violate the cross-chain supply invariant the bridge is designed to maintain.

---

### Likelihood Explanation

`migrate_deployed_token` is explicitly designed for legitimate operational use — replacing a faulty or upgraded token contract. A decimal change between versions is a realistic scenario (e.g., fixing a token deployed with the wrong decimal count, or migrating from a 24-decimal NEAR-native token to an 18-decimal EVM-mirrored one). The DAO does not need to be malicious; a routine migration with a decimal mismatch is sufficient to trigger the vulnerability for all users who subsequently call `SwapMigratedToken`.

---

### Recommendation

1. In `migrate_deployed_token`, read the `decimals` field from `token_decimals` for both `old_token` and `new_token` (via their shared `origin_address`) and `require!` they are equal before proceeding.
2. Alternatively, if decimal changes must be supported, `swap_migrated_token` must apply the same `normalize_amount` / `denormalize_amount` scaling used elsewhere in the bridge: [4](#0-3) 

3. Emit an event from `migrate_deployed_token` that includes both tokens' decimal values so off-chain monitors can detect mismatches before users are harmed.

---

### Proof of Concept

**Setup:**
- `old_token` deployed with 24 decimals (standard NEAR fungible token).
- DAO calls `migrate_deployed_token(ChainKind::Eth, old_token, new_token)` where `new_token` was deployed with 18 decimals.

**Attack:**
1. Attacker holds `1e24` units of `old_token` (= 1.0 token at 24 decimals).
2. Attacker calls `old_token.ft_transfer_call(bridge, 1e24, '{"SwapMigratedToken":null}')`.
3. Bridge receives `ft_on_transfer(sender=attacker, amount=1e24, msg="SwapMigratedToken")`.
4. `swap_migrated_token` is invoked:
   - `ext_token::ext(old_token).burn(1e24)` — burns 1.0 old token. ✓
   - `ext_token::ext(new_token).mint(attacker, 1e24, None)` — mints `1e24` new tokens.
5. At 18 decimals, `1e24` new tokens = **1,000,000 new tokens** (1 million).
6. Attacker has converted 1 old token into 1,000,000 new tokens, extracting value from the bridge at a 1,000,000× ratio. [2](#0-1) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-283)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
    }
```

**File:** near/omni-bridge/src/lib.rs (L1604-1664)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn migrate_deployed_token(
        &mut self,
        origin_chain: ChainKind,
        old_token: AccountId,
        new_token: AccountId,
    ) {
        require!(
            env::attached_deposit() >= NEP141_DEPOSIT,
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

        require!(
            self.deployed_tokens.remove(&old_token),
            BridgeError::OldTokenNotDeployed.as_ref(),
        );
        require!(
            self.deployed_tokens.insert(&new_token),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2.remove(&old_token);
        self.deployed_tokens_v2.insert(&new_token, &origin_chain);

        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);

        require!(
            self.migrated_tokens
                .insert(&old_token, &new_token)
                .is_none(),
            BridgeError::TokenAlreadyMigrated.as_ref()
        );

        ext_token::ext(new_token.clone())
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .with_attached_deposit(NEP141_DEPOSIT)
            .storage_deposit(&env::current_account_id(), Some(true))
            .detach();

        env::log_str(
            &OmniBridgeEvent::MigrateTokenEvent {
                old_token_id: old_token,
                new_token_id: new_token,
            }
            .to_log_string(),
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L2738-2753)
```rust
    fn swap_migrated_token(
        &mut self,
        sender_id: AccountId,
        old_token: AccountId,
        amount: U128,
    ) -> Promise {
        let new_token = self
            .migrated_tokens
            .get(&old_token)
            .near_expect(BridgeError::TokenNotMigrated);

        let burn = ext_token::ext(old_token).burn(amount);
        let mint = ext_token::ext(new_token).mint(sender_id, amount, None);

        burn.and(mint)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2776-2787)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }

    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
