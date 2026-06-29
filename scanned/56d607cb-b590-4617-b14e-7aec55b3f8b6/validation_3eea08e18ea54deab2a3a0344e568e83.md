### Title
Fee-on-Transfer Token Mis-Accounting in Starknet `init_transfer` Causes Bridge Under-Collateralization — (File: `starknet/src/omni_bridge.cairo`)

---

### Summary

The Starknet `OmniBridge.init_transfer` function calls `transfer_from` with the user-supplied `amount` and then emits an `InitTransfer` event recording that same `amount` — without measuring the actual tokens received by the contract. For fee-on-transfer ERC20 tokens, the contract holds fewer tokens than the event claims, causing NEAR to mint more tokens than were locked on Starknet, permanently under-collateralizing the bridge.

---

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function handles non-bridge (native Starknet ERC20) tokens as follows:

```cairo
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
```

Immediately after, the event is emitted with the caller-controlled `amount`:

```cairo
self.emit(Event::InitTransfer(InitTransfer {
    ...
    amount,   // ← user-supplied, not actual received
    ...
}))
``` [1](#0-0) [2](#0-1) 

No balance snapshot is taken before or after the `transfer_from` call. The contract never computes `balance_after - balance_before` to determine the real deposit. The emitted `InitTransfer` event is the sole source of truth consumed by relayers and the NEAR prover to finalize the transfer on NEAR.

On the NEAR side, `fin_transfer_callback` reads the prover result (which is derived from the Starknet event), denormalizes the amount, and mints or unlocks that amount to the recipient:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [3](#0-2) 

NEAR unconditionally trusts the `amount` field from the verified Starknet event. There is no secondary check against actual Starknet contract balances.

---

### Impact Explanation

For any fee-on-transfer ERC20 registered as a non-bridge token on Starknet:

- Starknet contract receives `amount − fee_taken` tokens.
- Event records `amount`.
- NEAR mints `amount` tokens to the recipient.
- Net effect: recipient gains `fee_taken` tokens that were never locked, draining the bridge's Starknet-side reserves over repeated transfers.

This is a direct escrow mis-accounting / balance manipulation issue. The bridge becomes permanently under-collateralized for that token, and the shortfall grows with every transfer. This falls squarely within the **Critical** allowed impact scope: *balance manipulation, escrow mis-accounting that changes user or protocol balances*.

---

### Likelihood Explanation

**Low.** Exploitability requires a fee-on-transfer ERC20 to be registered with the bridge on both Starknet and NEAR. Token registration on NEAR involves admin-gated steps (`log_metadata`, token binding). However, the code contains no guard preventing a fee-on-transfer token from being registered, and the vulnerability is fully triggered by an unprivileged user once such a token exists in the registry. No admin compromise is required at exploit time — only at registration time, which is a normal operational step.

---

### Recommendation

Replace the fixed-`amount` pattern with a balance-check sandwich around the `transfer_from` call:

```cairo
let token = IERC20Dispatcher { contract_address: token_address };
let balance_before = token.balance_of(get_contract_address());
let success = token.transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
let balance_after = token.balance_of(get_contract_address());
let actual_received: u128 = (balance_after - balance_before).try_into().unwrap();
// Use actual_received in the emitted event instead of amount
```

Emit `actual_received` (not `amount`) in the `InitTransfer` event so that NEAR mints only what was truly locked.

---

### Proof of Concept

1. Deploy a Starknet ERC20 token with a 10% fee-on-transfer (i.e., `transfer_from(A, B, 1000)` moves only 900 to B and burns 100).
2. Register this token with the Omni Bridge on both Starknet and NEAR through the normal token-registration flow.
3. Call `OmniBridge.init_transfer(token_address, 1000, 0, 0, "near:attacker.near", "")`.
4. The contract receives 900 tokens; the `InitTransfer` event records `amount = 1000`.
5. A relayer submits the Starknet proof to NEAR `fin_transfer`.
6. NEAR's `fin_transfer_callback` reads `init_transfer.amount = 1000`, denormalizes, and mints 1000 tokens to `attacker.near`.
7. Attacker has received 1000 NEAR-side tokens while only 900 were locked on Starknet.
8. Repeating this drains the Starknet-side collateral by 100 tokens per iteration. [4](#0-3) [5](#0-4)

### Citations

**File:** starknet/src/omni_bridge.cairo (L281-331)
```text
        fn init_transfer(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u128,
            fee: u128,
            native_fee: u128,
            recipient: ByteArray,
            message: ByteArray,
        ) {
            assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

            assert(amount > 0, 'ERR_ZERO_AMOUNT');
            assert(fee < amount, 'ERR_INVALID_FEE');

            let origin_nonce = self.current_origin_nonce.read() + 1;
            self.current_origin_nonce.write(origin_nonce);

            let caller = get_caller_address();

            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
        }
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```
