### Title
Missing Destination Chain Validation in `init_transfer` Causes Permanent Burning of Bridged Tokens — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function in the NEAR omni-bridge contract does not validate that the user-supplied destination chain (encoded in `recipient: OmniAddress`) has a registered token address before irreversibly incrementing nonces and burning/locking tokens. The only destination check is that the chain is not `ChainKind::Near`. If a user provides a recipient on a chain that has no registered token address for the transferred token, the tokens are permanently burned with no on-chain recovery path.

---

### Finding Description

**Step 1 — Nonces are incremented before any destination-chain validation.**

In `init_transfer`, the only guard on the destination is:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

Immediately after, both the origin nonce and the per-chain destination nonce are incremented:

```rust
self.current_origin_nonce += 1;
let destination_nonce =
    self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());
``` [1](#0-0) 

There is no check that `get_token_address(destination_chain, token_id)` returns a valid address at this point.

**Step 2 — Tokens are burned/locked in `init_transfer_internal`.**

After the nonce increments, `init_transfer_internal` is called. For deployed (bridged) tokens it calls `burn_tokens_if_needed`, which fires a detached `burn` cross-contract call — irreversible:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [2](#0-1) 

**Step 3 — The only destination-chain validation happens in `sign_transfer`, after the irreversible state changes.**

`sign_transfer` (restricted to `#[trusted_relayer]`) is the function that actually validates the destination:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [3](#0-2) 

If the destination chain has no registered token address for the transferred token, `sign_transfer` panics every time it is called for this transfer ID. The transfer remains in `pending_transfers` indefinitely.

**Step 4 — No public cancel/recovery function exists.**

`remove_transfer_message` is an internal helper called only from `sign_transfer_callback` (on successful signing with zero fee) and `submit_transfer_to_utxo_chain_connector`. There is no externally callable `cancel_transfer` or equivalent that would allow the user or the DAO to recover funds from a stuck pending transfer. [4](#0-3) 

---

### Impact Explanation

For any deployed (bridged) token (e.g., wETH, wUSDC), the `burn` call is detached and non-reversible. Once `init_transfer_internal` completes successfully, the tokens no longer exist on NEAR. If `sign_transfer` can never succeed (because the destination chain has no registered token address for that token), the funds are permanently destroyed. This is a direct instance of **permanent freezing/loss of bridged funds**.

---

### Likelihood Explanation

The `OmniAddress` enum supports 12 chain variants (`Eth`, `Sol`, `Arb`, `Base`, `Bnb`, `Btc`, `Zcash`, `Pol`, `HyperEvm`, `Strk`, `Abs`, `Fogo`). [5](#0-4) 

Token addresses are registered per `(chain, token)` pair. A token registered for Ethereum is not automatically registered for Fogo or Abstract. Any user who provides a recipient on a chain that has not been configured for the specific token they are transferring will trigger this path. This is reachable by any unprivileged token holder via `ft_transfer_call` with a crafted `InitTransfer` message.

---

### Recommendation

Before incrementing nonces and entering `init_transfer_internal`, validate that the destination chain has a registered token address for the token being transferred:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        &token_id,
    ).is_some(),
    BridgeError::FailedToGetTokenAddress.as_ref()
);
```

This mirrors the check already present in `sign_transfer` and should be the gate that prevents nonce increments and token burns for unsupported destinations.

---

### Proof of Concept

1. User holds 100 `wETH` (a deployed/bridged token) on NEAR. `wETH` has a registered token address for `ChainKind::Eth` but not for `ChainKind::Fogo`.
2. User calls `ft_transfer_call` on the `wETH` contract with:
   ```json
   { "InitTransfer": { "recipient": "fogo:2xNweLHLqbS9YpP3UyaPrxKqgqoC6yPBFyuLxA8qtgr4", "fee": "0", "native_token_fee": "0" } }
   ```
3. `init_transfer` is entered:
   - `current_origin_nonce` incremented (e.g., becomes 42). [6](#0-5) 
   - `destination_nonces[Fogo]` incremented.
4. `init_transfer_internal` is called:
   - Transfer stored in `pending_transfers`.
   - `burn_tokens_if_needed` fires a detached `burn(100 wETH)` — tokens destroyed. [7](#0-6) 
   - `init_transfer_internal` returns `U128(0)` (no refund to `ft_on_transfer`).
5. A trusted relayer calls `sign_transfer({ origin_chain: Near, origin_nonce: 42 }, ...)`:
   - `get_token_address(ChainKind::Fogo, wETH_id)` returns `None`.
   - Contract panics: `ERR_FAILED_TO_GET_TOKEN_ADDRESS`. [3](#0-2) 
6. Transfer remains in `pending_transfers` forever. 100 wETH are permanently burned. No recovery path exists.

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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-types/src/lib.rs (L179-193)
```rust
pub enum OmniAddress {
    Eth(EvmAddress),
    Near(AccountId),
    Sol(SolAddress),
    Arb(EvmAddress),
    Base(EvmAddress),
    Bnb(EvmAddress),
    Btc(UTXOChainAddress),
    Zcash(UTXOChainAddress),
    Pol(EvmAddress),
    HyperEvm(EvmAddress),
    Strk(StarknetAddress),
    Abs(EvmAddress),
    Fogo(SolAddress),
}
```
