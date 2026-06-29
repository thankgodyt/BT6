### Title
Fee Transfer to Relayer Silently Fails While `locked_tokens` Accounting Is Already Updated — (File: `near/omni-bridge/src/lib.rs`)

### Summary

In `fin_transfer_send_tokens_callback`, the fee payment to the relayer for non-deployed (custodied) tokens uses `ft_transfer(...).detach()` — a fire-and-forget call with no success check. If this transfer fails silently (e.g., a non-reverting NEP-141 token), the fee tokens remain permanently stuck in the bridge while `locked_tokens` has already been decremented by the full transfer amount. The `FinTransferEvent` is emitted regardless, falsely signaling complete success.

### Finding Description

The inbound finalization flow (`Foreign → NEAR`) proceeds as follows:

**Step 1 — `process_fin_transfer_to_near`** calls `unlock_tokens_if_needed` with the **full** `transfer_message.amount` (principal + fee), permanently decrementing `locked_tokens` before any token movement occurs. [1](#0-0) 

**Step 2** — The principal (`amount_without_fee`) is sent to the recipient via `send_tokens(...).then(fin_transfer_send_tokens_callback(...))`. This leg has a proper callback. [2](#0-1) 

**Step 3 — Inside `fin_transfer_send_tokens_callback`**, on the success branch, the fee portion is dispatched to the relayer via a **detached** `ft_transfer`: [3](#0-2) 

The result of this `ft_transfer` is never observed. Immediately after, `FinTransferEvent` is emitted unconditionally: [4](#0-3) 

If the `ft_transfer` fails silently (a non-reverting NEP-141 token returns without panicking, or the fee recipient's storage is unregistered between the earlier storage-balance check and this call), the fee tokens remain in the bridge contract with no on-chain record and no recovery path.

The `locked_tokens` map was already decremented by the full amount in Step 1: [5](#0-4) 

### Impact Explanation

- `locked_tokens` permanently underestimates the actual tokens held by the bridge (decremented by `amount`, but only `amount_without_fee` left the bridge). The `fee` tokens are stranded with no accounting entry.
- The `FinTransferEvent` falsely signals that the full transfer — including fee delivery — succeeded. Off-chain relayer infrastructure and indexers will record the fee as paid.
- The fee tokens are permanently unrecoverable through any normal bridge operation. The DAO can correct `locked_tokens` via `set_locked_tokens`, but cannot extract the stranded tokens without a dedicated rescue function.
- This is a direct escrow mis-accounting and fee mis-accounting impact: the bridge's internal ledger diverges from its actual token balance.

### Likelihood Explanation

Non-deployed tokens are external contracts not controlled or audited by the bridge. A NEP-141 token that returns without panicking on a failed `ft_transfer` (analogous to ERC-20 tokens that return `false`) is the primary trigger. Additionally, a fee recipient that unregisters storage between the storage-balance check in `process_fin_transfer_to_near` and the actual `ft_transfer` in the callback would also trigger this. Both scenarios are reachable by any bridge user who initiates a transfer with a non-zero fee using a non-standard token.

### Recommendation

Replace the detached fee `ft_transfer` with a chained callback that verifies success. If the fee transfer fails, the callback should either retry or restore `locked_tokens` to its pre-call value. Concretely:

```rust
// Instead of:
ext_token::ext(token)
    .with_attached_deposit(ONE_YOCTO)
    .with_static_gas(FT_TRANSFER_GAS)
    .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
    .detach();

// Use a chained callback:
ext_token::ext(token)
    .with_attached_deposit(ONE_YOCTO)
    .with_static_gas(FT_TRANSFER_GAS)
    .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(FEE_TRANSFER_CALLBACK_GAS)
            .fee_transfer_callback(token, fee_amount, chain_kind),
    );
```

The callback should re-lock the fee amount in `locked_tokens` if the transfer failed, preventing the accounting discrepancy.

### Proof of Concept

1. A non-standard NEP-141 token (non-reverting on failure) is registered with the bridge as a non-deployed (custodied) token.
2. A user on a foreign chain locks `1000` units and specifies a fee of `100` units, with a relayer as fee recipient.
3. The relayer submits the proof via `fin_transfer`. `process_fin_transfer_to_near` runs: `unlock_tokens_if_needed` decrements `locked_tokens` by `1000`.
4. `send_tokens` delivers `900` units to the recipient. The callback `fin_transfer_send_tokens_callback` fires.
5. Inside the callback, `ft_transfer(relayer, 100, None).detach()` is called. The token contract returns without panicking (non-reverting failure). The `100` fee tokens remain in the bridge.
6. `FinTransferEvent` is emitted, indicating full success.
7. `locked_tokens` now reads `0` for this token/chain pair, but the bridge holds `100` untracked tokens. The accounting discrepancy is permanent. [6](#0-5) [1](#0-0)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1719-1746)
```rust
        } else {
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }

            env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
        }
```

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1957-1977)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
                .fin_transfer_send_tokens_callback(
                    transfer_message,
                    &fee_recipient,
                    !msg.is_empty(),
                    predecessor_account_id,
                    lock_actions,
                ),
        )
```

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```
