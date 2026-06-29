### Title
`is_refund_required` Silently Ignores `ft_transfer_call` Promise Failures, Permanently Locking Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`is_refund_required` in `near/omni-bridge/src/lib.rs` returns `false` ("don't refund / treat as success") when the underlying `ft_transfer_call` promise fails with a protocol-level error (`Err(_)`). All three callbacks that rely on this function — `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer` — then proceed down the "success" path, permanently finalizing a transfer whose tokens were never delivered to the recipient.

---

### Finding Description

`is_refund_required` distinguishes two outcomes of a `ft_transfer_call` promise: [1](#0-0) 

```
Ok(value) → parse U128 used-amount → refund iff used == 0
Err(_)    → "Unexpected case: don't refund" → false
```

The `Ok` branch correctly handles the NEP-141 happy path: `ft_resolve_transfer` returns the **used** amount; if it is zero (meaning `ft_on_transfer` rejected or panicked), `is_refund_required` returns `true` and the bridge reverts state.

The `Err` branch is the bug. A NEAR promise result is `Err` when the cross-contract call itself fails at the protocol level — for example:

- The token contract panics inside `ft_transfer_call` before `ft_resolve_transfer` can run (e.g., the token is paused, an invariant check fires, or the contract is upgraded mid-flight).
- Gas exhaustion during the `ft_transfer_call → ft_on_transfer → ft_resolve_transfer` chain causes the entire sub-tree to fail.
- The `mint` path for deployed tokens (line 2094–2101) calls `mint` with a `msg`, which internally calls `ft_transfer_call`; if that inner call fails at the protocol level, the outer promise result is `Err`. [2](#0-1) 

In all these cases the NEP-141 token contract reverts the transfer (tokens return to the bridge's balance), but `is_refund_required` returns `false`, so every caller treats the delivery as successful.

**`fin_transfer_send_tokens_callback`** (primary impact): [3](#0-2) 

When `is_refund_required` returns `false`, the function skips `revert_lock_actions`, skips `remove_fin_transfer`, and emits `FinTransferEvent`. The transfer ID was already inserted into `finalised_transfers` by `add_fin_transfer` earlier in `process_fin_transfer_to_near`: [4](#0-3) 

Result: the transfer is permanently marked finalized, the `locked_tokens` counter was already decremented (unlocked), and the tokens sit in the bridge's own balance with no recovery path.

**`resolve_fast_transfer`** (secondary impact): [5](#0-4) 

`burn_tokens_if_needed` is called unconditionally, then `is_refund_required` returns `false`, so the fast-transfer record is not removed and the relayer receives no refund (`U128(0)`). The relayer's tokens are burned with no compensation.

**`resolve_utxo_fin_transfer`** (tertiary impact): [6](#0-5) 

Same pattern: when `is_refund_required` returns `false` on a promise error, the UTXO transfer is logged as successful while the tokens were never delivered.

---

### Impact Explanation

For inbound transfers with a non-empty `msg` (the `ft_transfer_call` path in `send_tokens`): [7](#0-6) 

If the promise fails at the protocol level:
1. The token contract reverts — tokens return to the bridge's balance.
2. `fin_transfer_send_tokens_callback` treats the result as success.
3. The transfer ID is in `finalised_transfers` — it cannot be replayed.
4. `locked_tokens` was decremented — accounting is permanently wrong.
5. The user's bridged funds are stuck in the bridge contract forever with no admin recovery function.

This is a **permanent, irrecoverable loss of bridged funds** for any user whose inbound cross-chain transfer with a `msg` field encounters a protocol-level `ft_transfer_call` failure.

---

### Likelihood Explanation

The trigger condition — a promise-level `Err` rather than an `Ok(U128(0))` — is reachable without any privileged access:

- Any user who specifies a non-empty `msg` in their cross-chain transfer (to invoke a DeFi protocol on NEAR) is on the affected code path.
- Gas exhaustion in a complex `ft_on_transfer` handler (e.g., a DEX swap, lending protocol deposit) causes the entire `ft_transfer_call` sub-tree to fail with `Err`, not `Ok`.
- A token contract that is paused or has an access-control check on `ft_transfer_call` will also produce `Err`.
- The bridge's gas budget for `ft_transfer_call` is computed dynamically and capped at `FT_TRANSFER_CALL_GAS`; a receiver that consumes more gas than this cap will trigger the failure. [8](#0-7) 

No admin compromise, MPC collusion, or validator attack is required. A normal user sending to a gas-heavy DeFi contract is sufficient.

---

### Recommendation

Change the `Err` arm of `is_refund_required` to return `true` (treat a protocol-level failure as "refund required"):

```rust
// Unexpected case: promise failed at protocol level — tokens were not delivered,
// so a refund/revert IS required.
Err(_) => true,
``` [9](#0-8) 

This ensures that when `ft_transfer_call` fails at the protocol level, all three callbacks (`fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, `resolve_utxo_fin_transfer`) correctly revert bridge state and return tokens to the user or relayer.

---

### Proof of Concept

1. User initiates a transfer from Ethereum to NEAR with `msg = "<dex-swap-payload>"` (non-empty), bridging 1000 USDC.
2. Relayer submits proof via `fin_transfer`. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer` inserts the transfer ID into `finalised_transfers`.
   - `unlock_tokens_if_needed` decrements `locked_tokens[USDC]` by 1000.
   - `send_tokens` dispatches `ft_transfer_call(dex_contract, 1000, msg)`.
3. The DEX contract's `ft_on_transfer` consumes more gas than the allocated `FT_TRANSFER_CALL_GAS`. The entire `ft_transfer_call` sub-tree fails; NEAR reverts the token transfer (1000 USDC returns to bridge balance).
4. `fin_transfer_send_tokens_callback` is invoked. `is_refund_required(true)` calls `env::promise_result_checked(0, ...)` which returns `Err(_)` → returns `false`.
5. The callback takes the `else` branch: emits `FinTransferEvent`, sends fee to relayer. No state revert.
6. The transfer ID is permanently in `finalised_transfers`. `locked_tokens[USDC]` is 1000 lower than the actual bridge balance. The user's 1000 USDC is locked in the bridge contract with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1014-1044)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
```rust
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
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
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1885)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L2063-2067)
```rust
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);
```

**File:** near/omni-bridge/src/lib.rs (L2082-2101)
```rust
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
```

**File:** near/omni-bridge/src/lib.rs (L2107-2117)
```rust
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
```
