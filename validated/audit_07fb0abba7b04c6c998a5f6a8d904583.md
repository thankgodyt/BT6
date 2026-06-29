Let me look at the `add_fin_transfer` function and the `is_refund_required` logic more carefully to confirm the full impact.

Now I have a complete picture of the code. Let me trace the full execution path.

**Key findings from the code:**

1. `add_fin_transfer` inserts the transfer ID into `self.finalised_transfers` (a permanent set) — no removal in the success path.
2. `is_refund_required(false)` unconditionally returns `false` when `msg.is_empty()` — it never checks the `ft_transfer` promise result.
3. There is **no guard** anywhere in `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` preventing `recipient == env::current_account_id()`.

---

### Title
Missing Self-Recipient Guard Causes Permanent Freezing of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

`process_fin_transfer_to_near` accepts any `AccountId` as recipient, including the bridge contract itself. When `recipient == locker_contract_id`, the subsequent `ft_transfer` (native tokens) fails silently because NEP-141 forbids self-transfer, while `mint` (deployed tokens) succeeds and deposits tokens into the bridge. In both cases `add_fin_transfer` permanently marks the nonce as finalised, and `fin_transfer_send_tokens_callback` never reverts state when `msg` is empty. The user's funds are permanently frozen with no on-chain recovery path.

### Finding Description

**Execution path:**

`fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` → `fin_transfer_send_tokens_callback`

**Step 1 — No recipient guard.**
`fin_transfer_callback` extracts `recipient` from the prover result and passes it directly to `process_fin_transfer_to_near` with no check that `recipient != env::current_account_id()`. [1](#0-0) 

**Step 2 — Transfer permanently marked finalised before token send.**
`add_fin_transfer` inserts the transfer ID into `self.finalised_transfers`. This is never undone in the success path. [2](#0-1) 

**Step 3 — `locked_tokens` counter decremented before token send.**
`unlock_tokens_if_needed` decrements the accounting counter before `send_tokens` is called. [3](#0-2) 

**Step 4 — `send_tokens` issues a self-directed call.**

- *Native NEP-141 token*: calls `ft_transfer(locker_contract_id, amount, None)`. NEP-141 requires `receiver_id != predecessor_account_id`; since the bridge is the caller and the receiver, this call **fails**.
- *Deployed/bridged token*: calls `mint(locker_contract_id, amount, None)`. `mint` has no self-transfer restriction; it **succeeds**, depositing tokens into the bridge. [4](#0-3) [5](#0-4) 

**Step 5 — Callback ignores the failed promise result.**
`fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = !msg.is_empty()`. When `msg` is empty (the common case), `is_ft_transfer_call = false`, and `is_refund_required` unconditionally returns `false` without inspecting the promise result. The callback proceeds to the "success" branch, logs `FinTransferEvent`, and never calls `remove_fin_transfer` or `revert_lock_actions`. [6](#0-5) [7](#0-6) 

**Net state after the attack:**

| State | Native token | Deployed token |
|---|---|---|
| `finalised_transfers` | nonce inserted (permanent) | nonce inserted (permanent) |
| `locked_tokens` counter | decremented (accounting error) | decremented |
| Actual token balance of bridge | unchanged (ft_transfer failed) | increased by minted amount |
| User funds | permanently frozen | permanently frozen |
| Recovery path | none | none |

### Impact Explanation

Bridged funds are permanently frozen inside the bridge contract. The transfer nonce is consumed, so the transfer cannot be re-submitted. No admin or DAO function exists to recover tokens from this state. This matches the Critical impact category: *permanent freezing of bridged funds*.

### Likelihood Explanation

The attack requires a user on the source chain (e.g. Ethereum) to specify the bridge contract's NEAR account ID as the `recipient` field in `initTransfer`. This can happen accidentally (user error) or intentionally (griefing at the cost of the attacker's own tokens). The trusted relayer then faithfully relays the valid on-chain proof. No relayer compromise or proof forgery is required.

### Recommendation

1. **Add a self-recipient guard** in `process_fin_transfer_to_near`:
   ```rust
   require!(
       recipient != env::current_account_id(),
       BridgeError::InvalidRecipient.as_ref()
   );
   ``` [8](#0-7) 

2. **Check the `ft_transfer` promise result** in `fin_transfer_send_tokens_callback` regardless of `is_ft_transfer_call`. A failed `ft_transfer` (non-`ft_transfer_call` path) should trigger the same revert/refund logic as a failed `ft_transfer_call`. [9](#0-8) 

### Proof of Concept

```
1. On Ethereum, call initTransfer with:
     recipient = "<locker_contract_id>"   // bridge's own NEAR account ID
     token     = <any registered token>
     amount    = 1_000_000

2. Wait for the Ethereum event to be provable on NEAR.

3. Trusted relayer calls fin_transfer with:
     FinTransferArgs {
         chain_kind: ChainKind::Eth,
         storage_deposit_actions: [StorageDepositAction {
             token_id: <token>,
             account_id: <locker_contract_id>,   // bridge is already registered
             storage_deposit_amount: None,
         }],
         prover_args: borsh(ProverResult::InitTransfer(InitTransferMessage {
             recipient: OmniAddress::Near(<locker_contract_id>),
             ...
         })),
     }

4. Observe:
   - For native token: ft_transfer to self fails; callback ignores failure;
     finalised_transfers[nonce] = true; locked_tokens decremented; tokens stuck.
   - For deployed token: mint to self succeeds; tokens held by bridge;
     finalised_transfers[nonce] = true; no recovery path.

5. Assert: get_transfer_message(nonce) panics with TransferNotExist (never stored),
   and the nonce is in finalised_transfers, so re-submission panics with
   ERR_TRANSFER_ALREADY_FINALISED. Funds are permanently frozen.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L734-741)
```rust
        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
```

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

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
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
```

**File:** near/omni-bridge/src/lib.rs (L1867-1875)
```rust
    #[allow(clippy::too_many_lines, clippy::ptr_arg)]
    fn process_fin_transfer_to_near(
        &mut self,
        recipient: AccountId,
        predecessor_account_id: &AccountId,
        transfer_message: TransferMessage,
        storage_deposit_actions: &Vec<StorageDepositAction>,
    ) -> Promise {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L2094-2101)
```rust
            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
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
