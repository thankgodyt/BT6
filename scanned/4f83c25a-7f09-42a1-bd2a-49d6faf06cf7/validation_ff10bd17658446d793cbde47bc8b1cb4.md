### Title
Reentrancy in `init_transfer` Allows Creating Multiple Fraudulent Bridge Events Without Token Deposits — (File: `starknet/src/omni_bridge.cairo`)

---

### Summary

The `init_transfer` function in the Starknet OmniBridge contract has no reentrancy guard. A malicious or hook-enabled ERC20 token can reenter `init_transfer` during the `transfer_from` call, creating multiple `InitTransfer` events with distinct nonces but without corresponding token deposits. Each event is independently accepted by NEAR's `fin_transfer_callback`, resulting in unauthorized minting of bridged tokens on NEAR.

---

### Finding Description

In `starknet/src/omni_bridge.cairo`, `init_transfer` follows this sequence:

1. Increments `current_origin_nonce` (state update) — lines 295–296
2. Calls `transfer_from` on the caller-supplied `token_address` (external call) — lines 304–306
3. Optionally calls `transfer_from` on the native fee token (second external call) — lines 311–313
4. Emits the `InitTransfer` event — lines 316–330 [1](#0-0) 

The nonce is incremented before the external call, which prevents nonce reuse within a single call. However, there is **no reentrancy guard**. Starknet's execution model permits synchronous reentrancy through external contract calls. A malicious ERC20 token whose `transfer_from` implementation reenters `init_transfer` will cause the nonce to be incremented again and a new `InitTransfer` event to be emitted — each with a unique, valid nonce — before the outer call's event is emitted. The malicious token can return `true` from `transfer_from` without actually transferring any tokens, so both events are emitted with zero real token deposit.

The bridge accepts any `token_address` without a whitelist check for non-bridge tokens:

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
``` [2](#0-1) 

On the NEAR side, `fin_transfer_callback` accepts any `InitTransfer` proof whose `emitter_address` matches the registered Starknet factory. The Starknet bridge contract itself is that factory, so every event it emits — including reentrant ones — passes the factory check:

```rust
require!(
    self.factories
        .get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [3](#0-2) 

NEAR then mints or unlocks tokens for each independently verified event.

---

### Impact Explanation

Each `InitTransfer` event emitted by the Starknet bridge is independently verified by NEAR's MPC prover and processed by `fin_transfer_callback`, which mints or unlocks the corresponding token amount for the recipient. If N+1 events are created via reentrancy with zero actual token deposit, NEAR mints (N+1) × amount tokens for the attacker. This constitutes **unauthorized minting of bridged tokens** — a critical loss of funds from the bridge's token supply.

---

### Likelihood Explanation

The attack requires a token with reentrancy capability (a malicious ERC20 with a hook in `transfer_from`, or a legitimate token upgraded to ERC777-style semantics) that is also registered in NEAR's token registry. Any unprivileged user can deploy such a token on Starknet. The condition is analogous to the ConvexMasterChef finding, which was rated Medium precisely because it was conditional on the reward token having transfer flow control. Here the condition is that the token used in `init_transfer` has a reentrant `transfer_from` — a realistic scenario for any custom or upgradeable token.

---

### Recommendation

Add a reentrancy guard to `init_transfer`. Since OpenZeppelin's Starknet library does not yet ship a `ReentrancyGuard` component, implement one with a storage boolean:

```cairo
// In Storage
reentrancy_guard: bool,

// At the top of init_transfer
assert(!self.reentrancy_guard.read(), 'ERR_REENTRANT_CALL');
self.reentrancy_guard.write(true);
// ... body ...
self.reentrancy_guard.write(false);
```

Alternatively, follow strict checks-effects-interactions ordering by emitting the `InitTransfer` event **before** any external token call, so that the observable state is committed before control is transferred to the token contract.

---

### Proof of Concept

1. Attacker deploys `MaliciousToken` on Starknet. Its `transfer_from(from, to, amount)` implementation:
   - Reenters `OmniBridge.init_transfer(MaliciousToken, amount, fee, ...)` once
   - Returns `true` without moving any tokens
2. Attacker calls `OmniBridge.init_transfer(MaliciousToken, X, 0, ...)`.
3. Bridge increments nonce to N, calls `MaliciousToken.transfer_from(attacker, bridge, X)`.
4. `MaliciousToken.transfer_from` reenters `init_transfer`:
   - Nonce increments to N+1
   - Calls `MaliciousToken.transfer_from` again → returns `true` (no transfer)
   - Emits `InitTransfer { nonce: N+1, token: MaliciousToken, amount: X, recipient: attacker }`
5. Control returns to outer call; `transfer_from` returns `true` (no transfer).
6. Outer call emits `InitTransfer { nonce: N, token: MaliciousToken, amount: X, recipient: attacker }`.
7. Relayer submits both proofs to NEAR `fin_transfer`.
8. NEAR's MPC prover verifies both events (both were genuinely emitted by the registered Starknet factory).
9. NEAR mints 2X tokens for the attacker; 0 tokens were ever deposited on Starknet. [4](#0-3) [5](#0-4)

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
