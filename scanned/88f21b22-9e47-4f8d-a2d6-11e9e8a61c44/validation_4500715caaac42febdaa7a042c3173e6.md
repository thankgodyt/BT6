### Title
Unchecked `burn` Promise Result in `burn_tokens_if_needed` Allows Token Supply Inflation Without Burning — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR bridge's `burn_tokens_if_needed` fires a cross-contract `burn` call with `.detach()`, discarding the promise result entirely. If the burn fails for any reason, the `InitTransferEvent` is still emitted and the bridge proceeds as if the burn succeeded, allowing the relayer to mint tokens on the destination chain while the bridge retains the tokens that should have been destroyed.

---

### Finding Description

In `init_transfer_internal`, when a user bridges a NEAR-deployed bridge token back to its origin chain, the flow is:

1. User calls `ft_transfer_call` on the bridge token, transferring tokens to the bridge contract.
2. The bridge's `ft_on_transfer` callback calls `init_transfer_internal`.
3. `burn_tokens_if_needed` is called, which schedules a cross-contract `burn` call using `.detach()`.
4. `InitTransferEvent` is logged unconditionally.
5. `ft_on_transfer` returns `U128(0)` (all tokens consumed).

The critical flaw is at step 3: [1](#0-0) 

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result never checked
    }
}
```

`.detach()` is NEAR's equivalent of ignoring the return value of `transfer`/`transferFrom`. The burn promise is scheduled but its success or failure is never observed. The `InitTransferEvent` is emitted regardless: [2](#0-1) 

If the burn fails (e.g., `BURN_TOKEN_GAS` is insufficient, the token contract is paused, or any other revert condition), the bridge:
- Retains the tokens that were transferred to it (they were not burned).
- Still emits `InitTransferEvent`, causing the relayer to finalize the transfer on the destination chain and mint tokens there.

---

### Impact Explanation

This is a **token supply inflation / escrow mis-accounting** vulnerability. The bridge-minted token supply on NEAR is not reduced (burn silently failed), yet new tokens are minted on the destination chain. The total circulating supply across chains exceeds what was originally locked/minted, permanently breaking the 1:1 peg invariant. Funds are effectively created from nothing on the destination chain.

---

### Likelihood Explanation

The burn can fail if `BURN_TOKEN_GAS` is set too low (a misconfiguration that is not attacker-controlled but is a realistic operational condition), if the bridge token contract is paused, or if the token contract has any revert path in its `burn` function. While an unprivileged attacker cannot directly force the burn to fail, the absence of any failure handling means any such condition — including transient gas exhaustion — silently inflates supply. The bridge's own SECURITY.md confirms `.detach()` is used deliberately in multiple places, indicating this pattern is systemic. [3](#0-2) 

---

### Recommendation

Replace `.detach()` with a proper callback that checks the burn result. If the burn fails, the callback should refund the tokens to the sender and remove the pending transfer message, preventing the `InitTransferEvent` from being acted upon by the relayer. The pattern used elsewhere in the codebase (e.g., `fin_transfer` callbacks) demonstrates the correct approach.

---

### Proof of Concept

1. A bridge-deployed NEAR token (e.g., `wrapped-usdc.bridge.near`) is paused by its admin.
2. A user calls `ft_transfer_call` on `wrapped-usdc.bridge.near`, sending 1000 tokens to the bridge to bridge back to Ethereum.
3. The bridge's `ft_on_transfer` runs, calls `init_transfer_internal`, which calls `burn_tokens_if_needed`.
4. The `burn` cross-contract call is dispatched with `.detach()`. Because the token is paused, the burn reverts — but the bridge never observes this.
5. `InitTransferEvent` is emitted with `amount = 1000`.
6. The relayer picks up the event and calls `finTransfer` on the Ethereum `OmniBridge`, minting 1000 USDC to the user's Ethereum address.
7. The bridge contract on NEAR still holds 1000 `wrapped-usdc.bridge.near` tokens (burn failed). The user now has 1000 USDC on Ethereum AND the bridge holds 1000 tokens that should not exist — total supply is inflated by 1000. [1](#0-0) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1806-1812)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
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
        U128(0)
```

**File:** near/CLAUDE.md (L1-1)
```markdown
## Overview
```
