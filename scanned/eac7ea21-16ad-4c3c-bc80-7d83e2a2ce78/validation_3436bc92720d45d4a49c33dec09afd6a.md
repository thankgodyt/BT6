### Title
Rebasable NEP-141 Token as Bridged Asset Causes Permanent Freezing of Funds on Finalization - (File: near/omni-bridge/src/lib.rs)

### Summary

The NEAR Omni Bridge tracks locked token amounts using a strict integer counter (`locked_tokens`) and releases tokens during finalization using the recorded transfer amount, not the actual balance held. When a rebasable NEP-141 token is used, a negative rebase causes the bridge's actual token balance to fall below the recorded amount. The subsequent `ft_transfer` call in `process_fin_transfer_to_near` fails, but `fin_transfer_send_tokens_callback` does not handle plain `ft_transfer` failures — it only handles `ft_transfer_call` refunds. Because `add_fin_transfer` inserts the transfer ID into `finalised_transfers` before `send_tokens` is called, the transfer is permanently marked as finalized and cannot be retried. The user's tokens on the source chain are already burned/locked, and they receive nothing on NEAR.

### Finding Description

**Root cause — strict amount accounting in `locked_tokens`:**

When a user initiates a NEAR→other-chain transfer via `ft_on_transfer` → `init_transfer_internal`, the bridge records the exact transferred amount:

```rust
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,  // strict amount, not queried balance
);
```

The bridge holds the actual tokens in its account. If the token is rebasable and rebases downward, the bridge's actual balance becomes less than what `locked_tokens` records.

**Root cause — finalization marks transfer before releasing tokens:**

In `process_fin_transfer_to_near`:

```rust
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id()); // ← inserts into finalised_transfers FIRST
...
let lock_actions = vec![self.unlock_tokens_if_needed(...)]; // ← decrements locked_tokens
...
self.send_tokens(token.clone(), recipient, U128(amount_without_fee), &msg) // ← ft_transfer call
    .then(Self::ext(...).fin_transfer_send_tokens_callback(..., lock_actions))
```

`add_fin_transfer` inserts the `TransferId` into `finalised_transfers` before `send_tokens` is called. If `send_tokens` fails, the transfer is already permanently finalized.

**Root cause — callback does not handle `ft_transfer` failures:**

`fin_transfer_send_tokens_callback` only reverts lock actions when `is_refund_required` returns `true`. But `is_refund_required` only checks the promise result when `is_ft_transfer_call` is `true`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) { ... }
    } else {
        false  // ← always false for plain ft_transfer; failure is silently ignored
    }
}
```

`send_tokens` uses `ft_transfer` (not `ft_transfer_call`) when `msg.is_empty()`, which is the common case. So `is_ft_transfer_call = false`, and any `ft_transfer` panic is silently treated as success. The callback proceeds to the `else` branch, emits `FinTransferEvent`, and does not revert the finalization or the `unlock_tokens` action.

### Impact Explanation

**Negative rebase scenario:**
1. User bridges 1000 rebasable tokens NEAR→Eth. Bridge holds 1000 tokens; `locked_tokens[(Eth, token)] = 1000`.
2. Token rebases down: bridge now holds 900 tokens.
3. Relayer calls `fin_transfer` for a 1000-token return transfer (Eth→NEAR).
4. `add_fin_transfer` inserts the transfer ID into `finalised_transfers`.
5. `unlock_tokens_if_needed` decrements `locked_tokens` to 0.
6. `send_tokens` calls `ft_transfer(recipient, 1000)` — bridge only has 900 tokens → panic.
7. `fin_transfer_send_tokens_callback` is called; `is_refund_required` returns `false`; lock actions are NOT reverted; transfer is NOT removed from `finalised_transfers`.
8. Transfer is permanently finalized. User's Eth-side tokens are burned. User receives nothing on NEAR. **Permanent loss of bridged funds.**

**Positive rebase scenario (secondary):**
Extra rebased tokens accumulate in the bridge contract with no recovery mechanism, constituting a permanent loss for token holders.

### Likelihood Explanation

Rebasable NEP-141 tokens exist in the NEAR ecosystem (e.g., liquid staking derivatives). The bridge accepts any NEP-141 token via `ft_on_transfer` with no restriction on rebasable tokens. A negative rebase can occur due to slashing events or protocol-level adjustments. Any user can bridge a rebasable token; no privileged access is required. The trigger (rebase) is an inherent property of the token class, not an exotic attack.

### Recommendation

1. **Warn and document** that rebasable NEP-141 tokens must not be used as bridged assets on the NEAR side.
2. **Handle `ft_transfer` failures** in `fin_transfer_send_tokens_callback` by checking the promise result regardless of `is_ft_transfer_call`, and reverting `finalised_transfers` insertion and lock actions on failure.
3. **Alternatively**, move `add_fin_transfer` to after a successful `send_tokens` callback, so a failed transfer can be retried.

### Proof of Concept

**Step 1 — User bridges rebasable token NEAR→Eth:**
`ft_transfer_call(bridge, 1000, InitTransferMsg{recipient: eth_addr})` → `init_transfer_internal` records `locked_tokens[(Eth, token)] += 1000`.

**Step 2 — Token rebases down:**
Bridge account balance of the token drops from 1000 to 900 (external rebase event).

**Step 3 — Relayer finalizes return transfer Eth→NEAR:**
`fin_transfer(FinTransferArgs{chain_kind: Eth, prover_args: proof_of_1000_token_transfer})` → `fin_transfer_callback` → `process_fin_transfer_to_near`:

- `add_fin_transfer(&transfer_id)` → `finalised_transfers.insert(transfer_id)` = **true** (committed to state)
- `unlock_tokens_if_needed(Eth, token, 1000)` → `locked_tokens[(Eth, token)] = 0` (committed to state)
- `send_tokens(token, recipient, 1000, "")` → `ft_transfer(recipient, 1000)` → **panics** (bridge has only 900)

**Step 4 — Callback is called with failed promise:**
`fin_transfer_send_tokens_callback(transfer_message, fee_recipient, is_ft_transfer_call=false, lock_actions)`:
- `is_refund_required(false)` → `false`
- Enters `else` branch → emits `FinTransferEvent` (incorrect)
- Lock actions NOT reverted; `finalised_transfers` NOT cleaned up

**Result:** Transfer ID is permanently in `finalised_transfers`. `locked_tokens` is 0. Bridge holds 900 stranded tokens. User's Eth-side tokens are burned. User receives 0 tokens on NEAR. Funds are permanently frozen.

**Relevant code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```

**File:** near/omni-bridge/src/token_lock.rs (L48-94)
```rust
    fn lock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        let new_amount = current_amount
            .checked_add(amount)
            .near_expect(TokenLockError::LockedTokensOverflow);

        self.locked_tokens.insert(&key, &new_amount);

        LockAction::Locked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }

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
