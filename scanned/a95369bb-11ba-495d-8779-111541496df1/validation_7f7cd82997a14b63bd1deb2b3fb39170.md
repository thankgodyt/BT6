### Title
`fin_transfer_send_tokens_callback` Silently Treats Failed Token Delivery as Success, Permanently Locking Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When `fin_transfer` finalizes an inbound transfer to a NEAR recipient, the bridge marks the transfer as permanently finalized in `finalised_transfers` before the token delivery promise resolves. If the subsequent `ft_transfer` (or `near_withdraw`) call to the token contract fails, `fin_transfer_send_tokens_callback` incorrectly treats the failure as a success, emits a `FinTransferEvent`, and leaves the tokens permanently locked inside the bridge contract with no recovery path.

---

### Finding Description

The flow for inbound finalization to a NEAR recipient is:

1. `fin_transfer_callback` → `process_fin_transfer_to_near` (line 1875) calls `add_fin_transfer`, which inserts the transfer ID into `finalised_transfers` — a permanent replay-prevention set. [1](#0-0) 

2. `send_tokens` is then called (line 1957), which dispatches one of several external cross-contract calls depending on the token type:
   - `ft_transfer` for non-deployed tokens with an empty `msg` (line 2103–2106)
   - `near_withdraw` + `near_withdraw_callback` for wNEAR (lines 2071–2081)
   - `ft_transfer_call` for non-deployed tokens with a non-empty `msg` (lines 2113–2116) [2](#0-1) 

3. `fin_transfer_send_tokens_callback` is registered as the `.then()` callback (lines 1967–1977). Critically, this function has **no `#[callback_result]` parameter** — it never directly inspects whether the preceding promise succeeded or failed. [3](#0-2) 

4. The callback delegates entirely to `is_refund_required(is_ft_transfer_call)`. For the `ft_transfer` and `near_withdraw` paths, `is_ft_transfer_call` is `false` (set at line 1973 as `!msg.is_empty()`), so `is_refund_required` unconditionally returns `false` without ever reading the promise result: [4](#0-3) 

5. Even for the `ft_transfer_call` path (`is_ft_transfer_call = true`), if the promise itself errors (e.g., the token contract panics before returning), `is_refund_required` also returns `false`: [5](#0-4) 

6. With `is_refund_required` returning `false`, the callback takes the `else` branch: it pays the relayer fee and emits `FinTransferEvent` (success), without calling `remove_fin_transfer` or reverting `lock_actions`. [6](#0-5) 

The transfer ID remains in `finalised_transfers` permanently, blocking any replay. The tokens remain in the bridge contract with no mechanism to release them.

The `near_withdraw_callback` compounds this: when `near_withdraw` fails it calls `env::panic_str`, making the promise result for `fin_transfer_send_tokens_callback` an error — but since `is_ft_transfer_call` is `false` for wNEAR, the callback still treats it as success. [7](#0-6) 

---

### Impact Explanation

**Critical — Permanent loss of bridged funds.**

For any inbound transfer to a NEAR recipient where the token delivery fails:
- The transfer ID is permanently inserted into `finalised_transfers`, preventing any replay or re-finalization.
- The tokens (e.g., USDC, USDT, wNEAR) remain in the bridge contract with no admin recovery function.
- The relayer fee is paid out even though the recipient received nothing.
- The user's funds are irrecoverably lost.

This affects all non-deployed (native) tokens transferred to NEAR recipients with an empty `msg`, and all wNEAR-to-NEAR unwrap transfers.

---

### Likelihood Explanation

**Medium.** Realistic triggering conditions include:

- **USDC/USDT blacklisting**: Circle and Tether can blacklist specific NEAR addresses. If a recipient is blacklisted after a cross-chain transfer is initiated on the source chain but before `fin_transfer` is called on NEAR, the `ft_transfer` will revert and the funds are permanently lost.
- **Token contract pause**: USDC, USDT, and other regulated tokens have global pause mechanisms. Any in-flight transfer to a NEAR recipient during a pause window would be permanently lost.
- **wNEAR contract failure**: If `near_withdraw` fails for any reason (contract paused, insufficient balance due to a bug), the wNEAR is permanently locked.

No privileged access is required to trigger this — the failure is caused by the external token contract's behavior, which is outside the bridge's control.

---

### Recommendation

`fin_transfer_send_tokens_callback` must inspect the promise result for **all** delivery paths, not only `ft_transfer_call`. Specifically:

1. Add a `#[callback_result]` parameter to `fin_transfer_send_tokens_callback` to capture the promise outcome.
2. Extend `is_refund_required` (or replace it) to return `true` whenever the promise result is `Err(_)`, regardless of `is_ft_transfer_call`.
3. In the refund/revert branch, call `remove_fin_transfer` to allow the transfer to be re-submitted, or emit a `FailedFinTransferEvent` and provide a separate admin/user-triggered retry mechanism.
4. Apply the same fix to `resolve_utxo_fin_transfer` (lines 1016–1044), which has the identical structural flaw.

---

### Proof of Concept

**Scenario: USDC recipient is blacklisted**

1. User initiates transfer of 10,000 USDC from Ethereum to their NEAR account `alice.near` via the EVM bridge contract.
2. The EVM event is emitted; a relayer submits the proof to `fin_transfer` on NEAR.
3. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer` inserts the transfer ID into `finalised_transfers` (line 1875). [8](#0-7) 
   - `send_tokens` dispatches `ft_transfer(alice.near, 10000 USDC)` (line 2103–2106). [9](#0-8) 
4. The USDC contract rejects the transfer because `alice.near` is blacklisted. The promise fails.
5. `fin_transfer_send_tokens_callback` is called. `is_ft_transfer_call = false` (empty msg). `is_refund_required(false)` returns `false` unconditionally. [4](#0-3) 
6. The callback emits `FinTransferEvent` (success). The relayer fee is paid. [10](#0-9) 
7. The transfer ID remains in `finalised_transfers`. Any attempt to call `fin_transfer` again with the same proof panics with `TransferAlreadyFinalised`. [11](#0-10) 
8. 10,000 USDC is permanently locked in the bridge contract. `alice.near` receives nothing.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1047-1051)
```rust
    pub fn near_withdraw_callback(&self, recipient: AccountId, amount: NearToken) -> Promise {
        match env::promise_result_checked(0, usize::MAX) {
            Ok(_) => Promise::new(recipient).transfer(amount),
            Err(_) => env::panic_str(BridgeError::NearWithdrawFailed.to_string().as_str()),
        }
```

**File:** near/omni-bridge/src/lib.rs (L1692-1699)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
```

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

**File:** near/omni-bridge/src/lib.rs (L1797-1799)
```rust
                // Unexpected case: don't refund
                Err(_) => false,
            }
```

**File:** near/omni-bridge/src/lib.rs (L1800-1803)
```rust
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
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
