### Title
Deposit Proof Replay via Detached Burn Failure in `safe_mint_callback` — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

In the safe-deposit path, `safe_mint_callback` removes the UTXO's replay-protection entry from `verified_deposit_utxo` on failure, then fires a burn call with `.detach()` whose result is never checked. If the burn silently fails — which it will whenever the bridge contract holds no nBTC — the UTXO is permanently unguarded and the same BTC inclusion proof can be replayed to mint nBTC a second (or further) time.

### Finding Description

The safe-deposit flow ends in `safe_mint_callback`:

```
contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 421-468
```

When `is_refund_required()` returns `true` (the downstream DApp's `ft_on_transfer` returned a non-zero refund amount or panicked, so `safe_mint` returns `U128(0)` consumed), the callback executes three actions:

1. **Removes the UTXO from the replay guard** (`verified_deposit_utxo`): [1](#0-0) 

2. **Issues a detached burn from `env::current_account_id()` (the bridge itself)**: [2](#0-1) 

3. **Transfers NEAR back to the signer** (storage refund): [3](#0-2) 

The `is_refund_required` helper: [4](#0-3) 

Under standard NEP-141 `ft_transfer_call` semantics, when the receiver rejects the transfer, the tokens are returned to `recipient_id` (the depositor), **not** to the bridge contract. The bridge contract therefore holds zero nBTC. The `burn(env::current_account_id(), ...)` call will fail because the bridge has no balance to burn. Because the call is `.detach()`, this failure is silently discarded.

The net state after this failure path:

- `recipient_id` retains the minted nBTC (tokens were returned to them by the DApp rejection).
- `verified_deposit_utxo` no longer contains the UTXO key (it was removed at step 1).
- The same `tx_bytes` + `vout` + `proof` tuple is now accepted again by `verify_deposit_v2`.

The upstream guard that is supposed to prevent replay is the `require!` in `verify_deposit_callback` / `verify_safe_deposit_callback`: [5](#0-4) 

Because the key was removed, this guard passes on the second submission, and a second mint is issued for the same on-chain UTXO.

Contrast with the standard (non-safe) path: `mint_callback` also removes the key on failure, but that path is an intentional retry mechanism for transient mint errors. In the safe path the tokens are already in the user's wallet before the callback fires, so removal + silent burn failure = double-mint. [6](#0-5) 

### Impact Explanation

An attacker who can trigger the failure branch (DApp rejection) retains the first batch of minted nBTC and can immediately replay the same proof to receive a second batch. Repeating this mints unbacked nBTC, directly violating the 1:1 BTC-backing invariant. This maps to **Critical — Unauthorized minting of nBTC**.

### Likelihood Explanation

The `verify_deposit_v2` entry point is gated by `#[trusted_relayer]`: [7](#0-6) 

However, the wiki documents that when the `UnrestrictedRelayer` role is active, any NEAR account may submit proofs (subject to a higher confirmation delta). Under that configuration the attacker needs only a valid BTC inclusion proof and a DApp that rejects the transfer. The `internal_safe_verify_deposit` path does **not** call `check_deposit_msg` (which whitelists DApps for the standard path), so the attacker may freely specify any contract as the DApp target: [8](#0-7) 

Even with a restricted relayer set, a compromised or buggy whitelisted DApp that returns a non-zero refund amount is sufficient to trigger the path.

### Recommendation

1. **Do not remove the UTXO key on safe-mint failure.** The key should remain in `verified_deposit_utxo` permanently once inserted. If a retry is needed, a separate mechanism (e.g., an operator-gated reset) should be used.
2. **Check the burn result.** Replace `.detach()` with a chained callback that panics or emits an alert if the burn fails, so the inconsistency is surfaced rather than silently swallowed.
3. **Burn from `recipient_id`, not from the bridge.** If the DApp rejects and tokens are returned to `recipient_id`, the burn must target `recipient_id`, not `env::current_account_id()`.

### Proof of Concept

1. Attacker controls NEAR account `attacker.near` and a DApp contract `evil.near` whose `ft_on_transfer` always returns the full received amount (rejects all transfers).
2. Attacker (or a colluding relayer) calls `verify_deposit_v2` with a valid BTC proof, `deposit_msg.safe_deposit = Some(SafeDepositMsg { msg: <points to evil.near> })`, and `recipient_id = attacker.near`.
3. `verify_safe_deposit_callback` inserts the UTXO key into `verified_deposit_utxo` and calls `safe_mint(attacker.near, amount, msg)`.
4. `safe_mint` mints `amount` nBTC to `attacker.near`, then calls `evil.near::ft_on_transfer`, which returns `amount` (full refund). Tokens are returned to `attacker.near`. `safe_mint` returns `U128(0)`.
5. `safe_mint_callback` fires: `is_refund_required()` = true → UTXO key removed from `verified_deposit_utxo` → `burn(bridge, amount)` issued with `.detach()` → bridge has 0 nBTC → burn fails silently.
6. `attacker.near` holds `amount` nBTC. UTXO is unguarded.
7. Attacker replays step 2 with the identical proof. The `require!` guard passes (key absent). A second `amount` nBTC is minted to `attacker.near`.
8. Attacker now holds `2 × amount` nBTC backed by a single on-chain UTXO.

### Citations

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L399-403)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L439-441)
```rust
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L453-455)
```rust
            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L474-489)
```rust
fn is_refund_required() -> bool {
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Ok(value) => {
            if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                // Normal case: refund if the used token amount is zero
                // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                amount.0 == 0
            } else {
                // Unexpected case: don't refund
                false
            }
        }
        // Unexpected case: don't refund
        Err(_) => false,
    }
}
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L69-73)
```rust
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
        }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-73)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
```
