Audit Report

## Title
Bridge Contract Self-Referential `ft_on_transfer` via Crafted `msg` Enables Unauthorized Outbound Transfer Creation — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When a user crafts an EVM `initTransfer` with the NEAR bridge contract as recipient and a valid `BridgeOnTransferMsg::InitTransfer` JSON as `msg`, the trusted relayer's `fin_transfer` call causes the bridge to mint tokens to itself, re-enter its own `ft_on_transfer` via the token's `ft_transfer_call`, and create a new outbound `InitTransferEvent` targeting the attacker's EVM address. The relayer then signs this event via MPC in good faith, allowing the attacker to drain X tokens from the EVM bridge pool without a legitimate corresponding lock.

## Finding Description

**Root cause:** No check prevents the bridge contract itself from being the NEAR recipient of a finalized inbound transfer, and the user-supplied `msg` field is forwarded verbatim through the entire call chain.

**Code path:**

1. `fin_transfer_callback` (line 729) copies `init_transfer.msg` directly into `transfer_message.msg` with no sanitization. [1](#0-0) 

2. At line 734, if `recipient` is `OmniAddress::Near(bridge_contract_id)`, `process_fin_transfer_to_near` is called with no guard against the bridge being the recipient. [2](#0-1) 

3. `process_fin_transfer_to_near` (line 1897–1901) passes `transfer_message.msg` verbatim as `msg` to `send_tokens`. [3](#0-2) 

4. `send_tokens` (lines 2094–2101), for a deployed token with non-empty `msg`, calls `ext_token::mint(recipient, amount, Some(msg))`. [4](#0-3) 

5. Inside `omni-token`'s `mint`, when `msg` is `Some`, tokens are minted to `env::predecessor_account_id()` (the bridge contract), then `ft_transfer_call(account_id, amount, None, msg)` is called — where `account_id` is also the bridge contract. [5](#0-4) 

6. This triggers `bridge.ft_on_transfer(token_contract, X, crafted_msg)`. `ft_on_transfer` has no guard against the bridge being the receiver or the sender being the token contract acting on behalf of the bridge. [6](#0-5) 

7. `ft_on_transfer` parses the crafted `msg` as `BridgeOnTransferMsg::InitTransfer` and calls `init_transfer(sender_id=token_contract, signer_id=relayer, ...)`. The `signer_id` is the original transaction signer (the relayer), who is a trusted relayer with storage balance. [7](#0-6) 

8. `init_transfer_internal` stores the new `TransferMessage`, calls `burn_tokens_if_needed` (burning the X tokens just minted to the bridge), and emits `InitTransferEvent`. [8](#0-7) 

9. `ft_on_transfer` returns `U128(0)` (all tokens consumed). `ft_transfer_call` therefore returns `U128(X)` (full amount used). `fin_transfer_send_tokens_callback` sees `amount.0 != 0`, so `is_refund_required` returns `false` — no rollback occurs. [9](#0-8) 

10. `sign_transfer` (gated by `#[trusted_relayer]`) is called by the relayer on the newly created transfer, MPC signs the payload, and the attacker submits the signature to the EVM bridge to claim X tokens. [10](#0-9) 

**Why existing checks fail:**
- `fin_transfer` is gated by `#[trusted_relayer]`, but the relayer acts in good faith and cannot distinguish a malicious `msg` from a legitimate one.
- `init_transfer` checks that the recipient chain is not NEAR (line 531–534), but the attacker's target is an EVM address, so this check passes.
- `is_refund_required` only triggers a rollback when `ft_transfer_call` returns 0 (no tokens used), but in this attack `ft_on_transfer` returns 0 (all tokens consumed), so `ft_transfer_call` returns X and no rollback occurs. [11](#0-10) 

## Impact Explanation

This is a **Critical** impact: unauthorized release of bridged funds and escrow mis-accounting. The attacker's original X tokens remain locked in the EVM bridge from step 1, but the EVM bridge releases an additional X tokens to the attacker from other users' locked funds. The NEAR-side accounting is net-zero (mint then burn), making the attack invisible on NEAR while draining the EVM pool. This matches the allowed impact class: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds" and "Balance manipulation, escrow mis-accounting."

## Likelihood Explanation

The attacker only needs to:
1. Hold any bridgeable EVM token.
2. Call the public `initTransfer` function on the EVM bridge with `recipient = bridge_contract_near_id` and `msg = <crafted InitTransfer JSON>`.
3. Wait for any trusted relayer to submit the proof (normal bridge operation — relayers process all valid proofs automatically).

No privileged access, key compromise, or relayer collusion is required. The attack is repeatable for any amount the attacker can lock on EVM, and can be executed by any unprivileged EVM user.

## Recommendation

- In `process_fin_transfer_to_near`, add an explicit check rejecting transfers whose NEAR recipient is the bridge contract itself:
  ```rust
  require!(
      recipient != env::current_account_id(),
      BridgeError::InvalidRecipient.as_ref()
  );
  ```
- Alternatively, in `send_tokens`, when `recipient == env::current_account_id()`, force `msg` to be empty (use `ft_transfer` instead of `ft_transfer_call`/`mint(..., Some(msg))`).
- As defense-in-depth, in `ft_on_transfer`, reject calls where `env::predecessor_account_id()` is a deployed token controlled by the bridge and `sender_id` is the bridge contract itself.

## Proof of Concept

```
1. Attacker calls EVM OmniBridge.initTransfer(
       token = <any_deployed_bridged_token>,
       amount = X,
       recipient = "near:<bridge_contract_account_id>",
       msg = '{"InitTransfer":{"recipient":"eth:<attacker_evm_addr>","fee":"0","native_token_fee":"0"}}'
   )

2. Trusted relayer observes the EVM event, fetches proof, calls NEAR:
       bridge.fin_transfer(FinTransferArgs {
           chain_kind: Eth,
           prover_args: <proof>,
           storage_deposit_actions: [{ token_id: <token>, account_id: <bridge_contract> }]
       })

3. fin_transfer_callback: recipient = OmniAddress::Near(bridge_contract)
   → process_fin_transfer_to_near(bridge_contract, relayer, transfer_message, ...)

4. send_tokens(token, bridge_contract, X, crafted_msg)
   → token.mint(bridge_contract, X, Some(crafted_msg))
     → token.internal_deposit(bridge_contract, X)   // tokens minted to bridge
     → token.ft_transfer_call(bridge_contract, X, None, crafted_msg)
       → bridge.ft_on_transfer(token_contract, X, crafted_msg)

5. ft_on_transfer parses InitTransfer, calls init_transfer(
       sender_id = token_contract,
       signer_id = relayer,   // env::signer_account_id() = original tx signer
       token_id = token_contract,
       amount = X,
       recipient = eth:<attacker_evm_addr>
   )
   → init_transfer_internal: stores TransferMessage, burns X tokens from bridge,
     emits InitTransferEvent
   → ft_on_transfer returns U128(0)

6. ft_transfer_call returns U128(X) (all tokens used, no refund)
   fin_transfer_send_tokens_callback: is_refund_required = false → no rollback

7. Relayer calls bridge.sign_transfer(new_transfer_id, ...)
   → MPC signs payload for attacker's EVM address

8. Attacker submits MPC signature to EVM OmniBridge.finTransfer(...)
   → EVM bridge releases X tokens to attacker from other users' locked funds

Result: Attacker drains X tokens from EVM bridge pool.
         NEAR accounting: net zero (mint + burn). Attack is invisible on NEAR.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-264)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
```

**File:** near/omni-bridge/src/lib.rs (L444-448)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
```

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
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
```

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

**File:** near/omni-bridge/src/lib.rs (L1850-1863)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
```

**File:** near/omni-bridge/src/lib.rs (L1897-1901)
```rust
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
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

**File:** near/omni-token/src/lib.rs (L135-143)
```rust
        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
```
