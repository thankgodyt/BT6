### Title
Fee-on-Transfer Token Causes `locked_tokens` Mis-Accounting and Bridge Insolvency - (`File: near/omni-bridge/src/lib.rs`)

### Summary
The NEAR bridge's `ft_on_transfer` → `init_transfer` → `init_transfer_internal` flow records the NEP-141 `amount` parameter directly into `locked_tokens` and the `TransferMessage`, without verifying the actual token balance received. For fee-on-transfer (deflationary) NEAR-origin tokens, the bridge receives `amount - fee_on_transfer` but commits to releasing `amount` on the destination chain. This inflates `locked_tokens` relative to the bridge's real holdings, causing insolvency: later withdrawals fail permanently while the transfer is marked finalized.

### Finding Description

In NEP-141, `ft_on_transfer(sender_id, amount, msg)` is called with the *nominal* transfer amount. For a fee-on-transfer token, the bridge's actual balance increases by `amount - fee_on_transfer`, but `ft_on_transfer` still receives `amount`.

The bridge's `ft_on_transfer` dispatches to `init_transfer`: [1](#0-0) 

Inside `init_transfer`, the nominal `amount` is stored verbatim in the `TransferMessage`: [2](#0-1) 

`init_transfer_internal` then records this nominal amount in `locked_tokens`: [3](#0-2) 

`lock_tokens` simply adds the nominal amount to the stored counter: [4](#0-3) 

When the transfer is finalized on the destination chain and the user bridges back, `fin_transfer_callback` calls `unlock_tokens_if_needed` (decrementing `locked_tokens` by `amount`) and then `send_tokens` → `ft_transfer(recipient, amount)`: [5](#0-4) [6](#0-5) 

The bridge only holds `amount - fee_on_transfer` tokens, so `ft_transfer` panics. Critically, `fin_transfer_send_tokens_callback` does **not** revert the lock actions when `is_ft_transfer_call = false`: [7](#0-6) 

The transfer is marked finalized, `locked_tokens` is permanently decremented, but the recipient receives nothing.

The EVM side explicitly acknowledges this for EVM-locked tokens: [8](#0-7) 

The NEAR `CLAUDE.md` security notes contain **no equivalent acknowledgment** for NEAR-origin tokens: [9](#0-8) 

### Impact Explanation

For each deposit of a fee-on-transfer NEAR-origin token:
- Bridge receives `amount - fee_on_transfer` tokens (actual balance)
- Bridge records `amount` in `locked_tokens` and signs for `amount` on the destination chain
- Destination chain mints `amount` to recipient (over-minting relative to locked collateral)

On return withdrawal:
- `unlock_tokens` passes (counter is inflated, so `available >= amount`)
- `ft_transfer(recipient, amount)` panics (bridge lacks `amount` tokens)
- Transfer is finalized with no token delivery; `locked_tokens` is permanently decremented
- Repeated across multiple users: the bridge's collateral pool drains; later users cannot withdraw at all

This is permanent, irreversible loss of bridged funds — the bridge becomes insolvent for that token.

### Likelihood Explanation

A NEAR-origin token is registered via `bind_token`, which requires a valid cross-chain proof but is not admin-gated. A malicious actor can:
1. Deploy a fee-on-transfer NEP-141 token on NEAR
2. Deploy a corresponding token on a supported foreign chain
3. Submit a valid proof to `bind_token`
4. Attract users to bridge the token

Alternatively, a legitimately registered token that later introduces fee-on-transfer behavior (e.g., via an upgrade) triggers the same path with no further attacker action required.

### Recommendation

After `ft_on_transfer` is called, measure the actual balance change rather than trusting the `amount` parameter. One approach: query `ft_balance_of(env::current_account_id())` before and after the transfer (via a cross-contract call or by requiring the token to report actual received amount), and use the delta as the canonical locked amount. Alternatively, document and enforce that fee-on-transfer tokens are unsupported on the NEAR side (as is done in `evm/SECURITY.md`) and add an on-chain guard or allowlist check.

### Proof of Concept

1. Deploy a NEP-141 token `FeeToken` on NEAR that burns 1% on every transfer.
2. Register `FeeToken` with the bridge via `bind_token` (valid EVM proof).
3. Alice calls `ft_transfer_call(bridge, 1000, init_transfer_msg)`.
   - `FeeToken` transfers 1000; burns 10; bridge receives 990.
   - `ft_on_transfer` is called with `amount = 1000`.
   - Bridge records `locked_tokens[(Eth, FeeToken)] = 1000`.
   - MPC signs for 1000 on EVM; EVM mints 1000 to Alice.
4. Alice bridges 1000 back from EVM to NEAR.
   - EVM burns 1000; NEAR `fin_transfer` is called with `amount = 1000`.
   - `unlock_tokens` decrements `locked_tokens` to 0 (passes, counter was 1000).
   - `ft_transfer(Alice, 1000)` panics — bridge only holds 990.
   - `fin_transfer_send_tokens_callback` runs with `is_ft_transfer_call = false`; no revert.
   - Transfer finalized; Alice receives 0 tokens; 990 tokens are permanently stranded.

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-263)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L540-543)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
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

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1957-1966)
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
```

**File:** near/omni-bridge/src/token_lock.rs (L48-68)
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
```

**File:** evm/SECURITY.md (L7-7)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
```

**File:** near/CLAUDE.md (L181-230)
```markdown

### Common False Positives to Avoid

When auditing this codebase, these patterns are NOT vulnerabilities:

**1. Fast Transfer Fee Manipulation (NOT a vulnerability)**
- `FastTransferId` is computed from the entire struct including fee
- If relayer specifies wrong fee, IDs won't match when proof arrives
- Result: Relayer LOSES their fronted tokens, cannot profit
- The design is self-protecting

**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption

**3. Wormhole Emitter Chain (Correct Design)**
- Chain ID is explicitly encoded in the payload by source bridge (`OmniBridgeWormhole.sol:131-133`)
- Using `token_address.get_chain()` is correct - it reads the chain from the signed payload
- VAA's `emitter_chain` is a Wormhole-specific field; our protocol embeds chain in payload

**4. Gas Griefing via Storage Actions (NOT a vulnerability)**
- Caller provides their own `storage_deposit_actions`
- Bad inputs only harm the caller themselves (self-griefing)

**5. Signer ID Storage Manipulation (NOT profitable)**
- Attacker must spend their own tokens to create transfer
- Storage is refunded when transfer completes
- No profit mechanism for attacker

**6. Missing Emitter Validation in Prover (Correct Architecture)**
- Prover verifies cryptographic proof validity
- Bridge callback validates emitter against registered factories
- This separation of concerns is intentional and correct

**7. finish_withdraw_v2 Arbitrary Calls (Requires DAO Compromise)**
- Only callable by tokens in `deployed_tokens`
- `omni-token` (what bridge deploys) doesn't call this function
- Exploitation requires DAO to add malicious token (out of scope)

### Security Analysis Checklist

When reviewing changes to this codebase:

1. **Check overflow-checks**: Verify `Cargo.toml` still has `overflow-checks = true`
2. **Trace ID computations**: Changes to structs used in ID hashing affect matching logic
3. **Verify callback validation**: Ensure bridge callbacks validate emitter addresses
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
5. **Trust boundaries**: DAO, RbfOperator, UTXO Connectors are semi-trusted roles
6. **Storage refunds**: Ensure storage owners receive refunds on transfer completion
```
