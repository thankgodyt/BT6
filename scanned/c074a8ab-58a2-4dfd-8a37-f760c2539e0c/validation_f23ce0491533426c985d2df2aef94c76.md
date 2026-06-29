### Title
Unregistered-Token `init_transfer` Burns/Locks Funds With No Recovery Path — (`File: near/omni-bridge/src/lib.rs`)

### Summary
`init_transfer()` in the NEAR `omni-bridge` contract increments the per-chain `destination_nonce` and irreversibly burns or locks the user's tokens before verifying that the transferred token has a registered address on the destination chain. Because `sign_transfer()` hard-panics when the token mapping is absent, any transfer initiated for an unregistered `(chain, token)` pair permanently traps the user's funds with no on-chain recovery path.

### Finding Description
`init_transfer()` (called from `ft_on_transfer`) performs only two validations before mutating state:

1. The destination chain is not `ChainKind::Near`.
2. `fee < amount`.

It does **not** call `get_token_address(destination_chain, token_id)` to confirm the token is registered on the destination chain. [1](#0-0) 

Immediately after those checks, the per-chain `destination_nonce` is incremented unconditionally: [2](#0-1) 

`get_next_destination_nonce` writes the incremented value to persistent storage with no rollback: [3](#0-2) 

`init_transfer_internal` then burns deployed tokens and locks native tokens, returning `U128(0)` (no NEP-141 refund) on the happy path: [4](#0-3) 

The only place the token-registration check exists is in `sign_transfer()`, which is called **after** the burn/lock: [5](#0-4) 

`sign_transfer()` hard-panics with `BridgeError::FailedToGetTokenAddress` when the mapping is absent, so the transfer stored in `pending_transfers` can never be signed or completed. No public `cancel_transfer` or refund function exists in the contract.

### Impact Explanation
- **Deployed (bridged) tokens** — `burn_tokens_if_needed` destroys them permanently; they cannot be re-minted without a valid MPC-signed `finTransfer`.
- **Native NEAR tokens** — `lock_tokens_if_needed` traps them in the bridge's `locked_tokens` accounting; they cannot be unlocked without a completed transfer.

In both cases the user's funds are irrecoverably lost unless an admin manually registers the token on the destination chain and a relayer subsequently calls `sign_transfer()` — requiring out-of-band social coordination with no on-chain guarantee.

### Likelihood Explanation
The entry point is the standard NEP-141 `ft_transfer_call` flow, callable by any token holder. A user who sends a token to the bridge targeting a chain on which that token has not yet been registered (e.g., a token listed on Ethereum but not yet on Solana) will silently lose funds. The bridge UI or SDK provides no on-chain guard against this. The scenario is realistic during token-listing rollouts where a token is registered on some chains before others.

### Recommendation
Add a registration check at the top of `init_transfer()`, before any nonce increment or token operation:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        token_id.clone(),
    ).is_some(),
    BridgeError::TokenNotRegistered.as_ref()
);
```

This mirrors the fix applied in OmniPortal PR #1116 (`require(isSupportedChain(destChainId), …)`) and ensures that nonce increments and token burns/locks only occur for transfers that can actually be completed.

### Proof of Concept
1. Token `usdc.near` is registered on `ChainKind::Eth` but **not** on `ChainKind::Sol`.
2. User calls `usdc.near::ft_transfer_call(bridge, 1_000_000, InitTransfer { recipient: OmniAddress::Sol(...), fee: 0, ... })`.
3. `ft_on_transfer` → `init_transfer()`:
   - `destination_nonces[Sol]` incremented from 0 → 1. [6](#0-5) 
   - `init_transfer_internal` called; storage balance OK; `lock_tokens_if_needed(Sol, usdc.near, 1_000_000)` executes; returns `U128(0)`. [7](#0-6) 
4. NEP-141 refund = 0 → bridge keeps all 1 USDC.
5. Relayer calls `sign_transfer({origin_chain: Near, origin_nonce: N})`:
   - `get_token_address(Sol, usdc.near)` → `None` → `env::panic_str(FailedToGetTokenAddress)`. [5](#0-4) 
6. Transfer remains in `pending_transfers` indefinitely; 1 USDC is permanently frozen.

### Citations

**File:** near/omni-bridge/src/lib.rs (L462-469)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });
```

**File:** near/omni-bridge/src/lib.rs (L531-538)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());
```

**File:** near/omni-bridge/src/lib.rs (L1815-1827)
```rust
    fn get_next_destination_nonce(&mut self, chain_kind: ChainKind) -> Nonce {
        if chain_kind == ChainKind::Near {
            return 0;
        }

        let mut payload_nonce = self.destination_nonces.get(&chain_kind).unwrap_or_default();

        payload_nonce += 1;

        self.destination_nonces.insert(&chain_kind, &payload_nonce);

        payload_nonce
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
