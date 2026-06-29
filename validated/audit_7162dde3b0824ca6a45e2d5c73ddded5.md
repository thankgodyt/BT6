### Title
`resolve_fast_transfer` Burns Relayer Tokens Unconditionally Before Refund, Causing Permanent Loss of Bridged Funds - (File: near/omni-bridge/src/lib.rs)

### Summary

In `resolve_fast_transfer`, `burn_tokens_if_needed` is called **unconditionally** before checking whether a refund is required. When a fast transfer's internal `ft_transfer_call` to the NEAR recipient fails (recipient returns 0 from `ft_on_transfer`), the bridge burns the relayer's deposited tokens and then attempts to refund them — but the refund fails because the tokens no longer exist. The relayer permanently loses their bridged funds.

### Finding Description

`resolve_fast_transfer` is the final callback in the `fast_fin_transfer` → `fast_fin_transfer_to_near_callback` → `send_tokens` → `resolve_fast_transfer` chain for fast transfers to NEAR recipients. [1](#0-0) 

For deployed (bridged) tokens with a non-empty `msg`, `send_tokens` calls `mint(recipient, amount_without_fee, Some(msg))` on the token contract, which internally performs an `ft_transfer_call` to the recipient. [2](#0-1) 

If the recipient's `ft_on_transfer` returns 0 (rejection), `is_ft_transfer_call` is `true` and `is_refund_required` returns `true`. At this point, `resolve_fast_transfer` executes:

```rust
// Burn the tokens to ensure the locked tokens are not double-minted
self.burn_tokens_if_needed(token_id.clone(), amount);   // ← burns unconditionally

if Self::is_refund_required(is_ft_transfer_call) {
    self.remove_fast_transfer(fast_transfer_id);
    amount   // ← signals outer ft_transfer_call to refund `amount` to relayer
} else {
    U128(0)
}
``` [1](#0-0) 

The sequence of events:

1. Relayer sent `amount_total = amount_without_fee + fee` bridged tokens to the bridge via `ft_transfer_call`.
2. Bridge minted `amount_without_fee` to the recipient (which was rejected and burned by the token contract).
3. Bridge still holds `amount_total` tokens from the relayer.
4. `burn_tokens_if_needed` burns `amount_without_fee` from the bridge's balance (detached receipt, processed first).
5. `resolve_fast_transfer` returns `amount_without_fee`, signalling the outer `ft_transfer_call` to refund `amount_without_fee` to the relayer.
6. The token contract attempts to transfer `amount_without_fee` from bridge → relayer.
7. Bridge only holds `fee` tokens (burned `amount_without_fee` in step 4) → transfer fails.
8. Relayer receives nothing. `fee` tokens remain stuck in the bridge. [3](#0-2) 

The contrast with `fin_transfer_send_tokens_callback` makes the bug clear: that function correctly places `burn_tokens_if_needed` **inside** the `is_refund_required` branch, not before it. [4](#0-3) 

### Impact Explanation

A trusted relayer executing a fast transfer to a NEAR recipient contract that rejects `ft_transfer_call` permanently loses their `amount_without_fee` bridged tokens. The `fee` portion is additionally stuck in the bridge contract. This is a direct, permanent loss of bridged funds for the relayer.

### Likelihood Explanation

**Low.** The attack requires:
1. An attacker on a source chain (e.g., Ethereum) initiating a transfer whose NEAR recipient is a contract that always returns 0 from `ft_on_transfer`, and whose `msg` field is non-empty.
2. A trusted relayer choosing to fast-finalize that transfer.

The relayer is trusted but cannot always predict whether a recipient contract will accept `ft_transfer_call`. The attacker controls the recipient contract on NEAR and the cross-chain message parameters.

### Recommendation

Move `burn_tokens_if_needed` inside the `else` branch so it is only called when the transfer succeeded (no refund needed):

```rust
pub fn resolve_fast_transfer(...) -> U128 {
    if Self::is_refund_required(is_ft_transfer_call) {
        self.remove_fast_transfer(fast_transfer_id);
        amount
    } else {
        // Only burn when the transfer succeeded, to prevent double-minting
        self.burn_tokens_if_needed(token_id.clone(), amount);
        U128(0)
    }
}
```

### Proof of Concept

1. Attacker deploys a malicious NEAR contract `evil.near` whose `ft_on_transfer` always returns `"0"`.
2. Attacker initiates a cross-chain transfer from Ethereum to NEAR with `recipient = evil.near` and a non-empty `msg` (e.g., `"trigger"`).
3. A trusted relayer calls `ft_transfer_call(bridge, amount_total, FastFinTransfer{recipient: evil.near, msg: "trigger", ...})` on the

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2082-2101)
```rust
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
```
