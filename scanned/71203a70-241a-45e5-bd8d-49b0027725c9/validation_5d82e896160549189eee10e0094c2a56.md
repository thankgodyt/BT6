### Title
Unhandled `ft_transfer_call` Failure Causes Permanent Freezing of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

When `fin_transfer` delivers tokens to a NEAR recipient via `ft_transfer_call` (triggered by a non-empty `msg` field), and the recipient's `ft_on_transfer` panics, the bridge's `is_refund_required` helper incorrectly returns `false`. As a result, the transfer is permanently marked as finalised in `finalised_transfers` while the tokens remain locked in the bridge with no recovery path.

### Finding Description

The inbound transfer flow for NEAR recipients is:

1. `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` → `fin_transfer_send_tokens_callback`

Inside `process_fin_transfer_to_near`, when `msg` is non-empty, `send_tokens` issues an `ft_transfer_call` to the recipient contract. The callback `fin_transfer_send_tokens_callback` then calls `is_refund_required` to decide whether to revert the transfer: [1](#0-0) 

The critical branch is:

```rust
Err(_) => false,  // Unexpected case: don't refund
```

When `ft_on_transfer` panics on the recipient contract, NEAR rolls back the token transfer (tokens return to the bridge), and the promise result is `Err`. `is_refund_required` returns `false`, so the callback takes the non-refund path: [2](#0-1) 

The non-refund path:
- Does **not** call `remove_fin_transfer` — the `TransferId` stays permanently in `finalised_transfers`
- Does **not** call `revert_lock_actions` — `locked_tokens` accounting is permanently corrupted
- Emits `FinTransferEvent` as if the transfer succeeded [3](#0-2) 

Because `add_fin_transfer` uses `require!(self.finalised_transfers.insert(...))`, any subsequent attempt to re-submit the same proof will panic with `TransferAlreadyFinalised`. There is no admin escape hatch to remove a finalised transfer.

The `process_fin_transfer_to_near` function also calls `unlock_tokens_if_needed` before `send_tokens`, decrementing `locked_tokens`. Since `revert_lock_actions` is never called in the panic case, the accounting undercount is permanent. [4](#0-3) 

The integration test suite confirms this behaviour — when `panic: true`, `expected_locker_balance: 1000` (tokens stuck in bridge) for native tokens, and `expected_locker_balance: 0` (tokens burned/destroyed) for deployed tokens: [5](#0-4) 

### Impact Explanation

- **Native tokens**: Tokens are returned to the bridge by the token contract's rollback, but the transfer is permanently finalised. The user's funds are frozen in the bridge forever with no recovery mechanism.
- **Deployed (bridge-minted) tokens**: The `ft_transfer_call` rollback burns the minted tokens. The transfer is permanently finalised. The user's tokens are permanently destroyed.

Both outcomes constitute **permanent freezing or loss of bridged funds**, matching the Critical impact tier.

### Likelihood Explanation

Any user who bridges tokens with a non-empty `msg` field (to invoke `ft_on_transfer` on a recipient contract) is exposed. The panic can occur due to:
- A bug in the recipient DeFi contract
- Out-of-gas in `ft_on_transfer`
- A recipient contract that intentionally panics (e.g., rejects the transfer)
- Any unexpected revert in the recipient's callback logic

This is a normal, documented use case of the bridge (`msg` field exists precisely to enable `ft_transfer_call` flows). No privileged access is required — any bridge user with a non-empty `msg` is at risk.

### Recommendation

Change `is_refund_required` to return `true` when the `ft_transfer_call` promise fails:

```rust
// Before
Err(_) => false,  // Unexpected case: don't refund

// After
Err(_) => true,  // ft_transfer_call failed; trigger refund to allow retry
```

This ensures that when `ft_on_transfer` panics, the bridge:
1. Calls `remove_fin_transfer` (removes from `finalised_transfers`, enabling retry)
2. Calls `revert_lock_actions` (restores `locked_tokens` accounting)
3. Emits `FailedFinTransferEvent` (observable signal for relayers/users)

### Proof of Concept

1. User initiates a transfer from EVM to NEAR with `msg = '{"some":"payload"}'` targeting a recipient contract `R`.
2. A trusted relayer calls `fin_transfer` with a valid proof.
3. `fin_transfer_callback` calls `process_fin_transfer_to_near`, which:
   - Calls `add_fin_transfer` → `TransferId` inserted into `finalised_transfers`
   - Calls `unlock_tokens_if_needed` → `locked_tokens` decremented
   - Calls `send_tokens` → issues `ft_transfer_call` to `R`
4. `R.ft_on_transfer` panics (e.g., due to a bug or out-of-gas).
5. NEAR rolls back the token transfer; tokens return to bridge.
6. `fin_transfer_send_tokens_callback` is called: `is_refund_required` returns `false` (line 1798).
7. Bridge emits `FinTransferEvent`, does not call `remove_fin_transfer`.
8. User attempts to re-submit the proof → `fin_transfer_callback` panics with `ERR_TRANSFER_ALREADY_FINALISED`.
9. Tokens are permanently frozen in the bridge. No recovery path exists. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1692-1718)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
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

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1957-1978)
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
    }
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

**File:** near/omni-tests/src/fin_transfer.rs (L546-571)
```rust
    #[case(FinTransferWithMsgCase {
        storage_deposit_accounts: vec![(relayer_account_id(), true)],
        amount: 1000,
        fee: 1,
        msg: TokenReceiverMessage {
            return_value: U128(0),
            panic: true,
            extra_msg: String::new(),
        },
        expected_recipient_balance: 0,
        expected_relayer_balance: 0,
        expected_locker_balance: 1000,
    })]
    #[case(FinTransferWithMsgCase {
        storage_deposit_accounts: vec![],
        amount: 1000,
        fee: 0,
        msg: TokenReceiverMessage {
            return_value: U128(0),
            panic: true,
            extra_msg: String::new(),
        },
        expected_recipient_balance: 0,
        expected_relayer_balance: 0,
        expected_locker_balance: 1000,
    })]
```
