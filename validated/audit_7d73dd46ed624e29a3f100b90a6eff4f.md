### Title
Missing Recipient Validation in Starknet `init_transfer` Allows Permanent Token Loss — (`starknet/src/omni_bridge.cairo`)

---

### Summary

The `init_transfer` function in the Starknet `OmniBridge` contract validates `amount > 0` and `fee < amount`, but performs **no validation that the `recipient` ByteArray is non-empty**. A user who calls `init_transfer` with an empty `recipient` will have their tokens burned or locked on Starknet, while the resulting `InitTransfer` event is unfinalizeable on NEAR — causing permanent, irrecoverable loss of bridged funds.

---

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` entry point accepts a `recipient: ByteArray` parameter representing the destination address on the target chain. The function performs two input checks: [1](#0-0) 

```cairo
assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');
assert(amount > 0, 'ERR_ZERO_AMOUNT');
assert(fee < amount, 'ERR_INVALID_FEE');
```

There is **no assertion that `recipient` is non-empty**. Immediately after these checks, the contract irreversibly burns or locks the caller's tokens: [2](#0-1) 

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
```

Then it emits the `InitTransfer` event with the unvalidated (potentially empty) `recipient`: [3](#0-2) 

On the NEAR side, `fin_transfer_callback` parses the proof result and requires a valid `OmniAddress` recipient. An empty `ByteArray` cannot be parsed into a valid `OmniAddress`, so `fin_transfer` will panic and the transfer can never be finalized: [4](#0-3) 

There is no refund or recovery mechanism in either the Starknet or NEAR contracts for a transfer that was initiated but cannot be finalized. The tokens are permanently lost.

By contrast, the NEAR `init_transfer` path is protected because it is invoked via `ft_on_transfer` / `ft_transfer_call`, which enforces `amount > 0` at the NEP-141 token level, and separately validates the recipient chain: [5](#0-4) 

The Starknet contract is the only gateway that accepts a free-form `ByteArray` recipient with no non-emptiness check.

---

### Impact Explanation

A user who calls `init_transfer` with `recipient = ""` (empty ByteArray) will:
1. Have their tokens **permanently burned or locked** on Starknet.
2. Emit an `InitTransfer` event that no relayer can successfully finalize on NEAR.
3. Receive no refund — there is no on-chain recovery path.

This constitutes **permanent, irrecoverable loss of bridged funds**, matching the "Critical — Stealing, loss, or permanent freezing of bridged funds" impact category.

---

### Likelihood Explanation

The `init_transfer` function is a **public, permissionless entry point** callable by any Starknet account. A user can trivially pass an empty `ByteArray` as `recipient` either by mistake (e.g., a frontend bug, a misconfigured script) or deliberately (griefing their own funds). No special role, key, or privilege is required. The likelihood is **medium** — accidental miscalls are realistic given the free-form string parameter.

---

### Recommendation

Add an explicit non-empty check for `recipient` before any token movement occurs in `starknet/src/omni_bridge.cairo`:

```cairo
assert(recipient.len() > 0, 'ERR_EMPTY_RECIPIENT');
```

This mirrors the intent of the Solidity counterpart's `require(to != 0, "Invalid to address")` check and prevents tokens from being burned/locked against an unfinalizeable transfer.

---

### Proof of Concept

1. Attacker (or victim) calls `init_transfer(token_address, 1000, 0, 0, "", "")` on the Starknet `OmniBridge`.
2. `amount > 0` passes; `fee < amount` passes; no recipient check exists.
3. `IBridgeTokenDispatcher.burn(caller, 1000)` executes — tokens are permanently destroyed on Starknet.
4. `InitTransfer` event is emitted with `recipient = ""`.
5. Relayer submits proof to NEAR `fin_transfer`. `fin_transfer_callback` attempts to parse `""` as an `OmniAddress` and panics with `InvalidProofMessage`.
6. No retry or refund path exists. The 1000 tokens are permanently lost. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L700-713)
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
```
