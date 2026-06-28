### Title
NEAR-native tokens are permanently locked in `omni-bridge` when transferred to a chain where the token is not yet registered — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer` / `init_transfer_internal` path in the NEAR `omni-bridge` contract does not verify that the transferred token has a registered foreign-chain address before locking the user's tokens and emitting `InitTransferEvent`. A user can initiate a transfer of a NEAR-native token to EVM (or any foreign chain) where the token has never been deployed or bound. The tokens are immediately locked inside the bridge with no refund, but the subsequent `sign_transfer` call will always panic because `get_token_address` returns `None` for unregistered tokens. There is no cancel-transfer mechanism, so the tokens are frozen indefinitely.

### Finding Description

**Step 1 — Tokens are locked without a registration check.**

`init_transfer` (the private function called from `ft_on_transfer`) only checks that the recipient chain is not NEAR:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

It does **not** check whether the token has a registered address on the destination chain. It then calls `init_transfer_internal`, which:

1. Calls `burn_tokens_if_needed` — a no-op for non-deployed (NEAR-native) tokens.
2. Calls `lock_tokens_if_needed` — updates accounting.
3. Stores the transfer message in `pending_transfers`.
4. Emits `InitTransferEvent`.
5. Returns `U128(0)` — **zero tokens are refunded to the caller**.

The user's tokens are now held by the bridge contract with no path back.

**Step 2 — `sign_transfer` panics for unregistered tokens.**

When a relayer later calls `sign_transfer` to obtain the MPC signature needed to finalize the transfer on EVM, it calls:

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

`get_token_address` performs a lookup in `token_id_to_address`. For a NEAR-native token that has never been deployed or bound on the destination chain, this map has no entry and returns `None`, causing an unconditional panic. No MPC signature is ever produced, so `finTransfer` on EVM is never called.

**Step 3 — No recovery path exists.**

There is no public `cancel_transfer` or user-callable refund function. The transfer message sits in `pending_transfers` indefinitely. The only way the transfer could ever proceed is if the token is later registered on the destination chain — but if that never happens, the funds are permanently frozen.

### Impact Explanation

Any user who calls `ft_transfer_call` on a NEAR-native token pointing to a foreign chain where that token is not yet registered will have their entire transferred amount locked inside the bridge contract with no refund and no cancel path. This constitutes permanent freezing of bridged funds, matching the critical impact class.

### Likelihood Explanation

The scenario is realistic and reachable by any unprivileged token holder:
- NEAR has many native tokens (e.g., liquid-staking tokens, DeFi tokens) that may not yet be deployed on every supported EVM chain.
- The bridge UI/SDK does not prevent a user from specifying an EVM recipient for an unregistered token.
- A user who bridges a token before the corresponding `deploy_token` / `bind_token` step has been completed will trigger this path.
- No special role or privileged access is required.

### Recommendation

Add a registration check inside `init_transfer` (or `init_transfer_internal`) before locking tokens:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        token_id.clone(),
    ).is_some(),
    "Token not registered on destination chain"
);
```

Alternatively, add a user-callable `cancel_transfer` function that returns locked tokens when no MPC signature has yet been produced for a pending transfer.

### Proof of Concept

1. `token.near` is a NEAR-native token that has **not** been deployed on Ethereum (no entry in `token_id_to_address` for `(ChainKind::Eth, "token.near")`).
2. User calls `ft_transfer_call` on `token.near`, transferring 1000 tokens to the bridge with `msg = {"InitTransfer": {"recipient": "eth:0xRecipient", "fee": "0", "native_token_fee": "0"}}`.
3. Bridge's `ft_on_transfer` → `init_transfer` → `init_transfer_internal`:
   - `burn_tokens_if_needed("token.near", 1000)` → no-op (not a deployed token).
   - `lock_tokens_if_needed(ChainKind::Eth, "token.near", 1000)` → accounting updated.
   - Transfer message stored in `pending_transfers`.
   - `InitTransferEvent` emitted.
   - Returns `U128(0)` → **no refund**.
4. Relayer calls `sign_transfer(transfer_id, ...)`:
   - `get_token_address(ChainKind::Eth, "token.near")` → `None`.
   - Panics: `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
5. No MPC signature is produced; `finTransfer` on EVM is never called.
6. 1000 `token.near` tokens are permanently locked in the bridge contract. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L523-534)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1360-1376)
```rust
    pub fn get_token_address(
        &self,
        chain_kind: ChainKind,
        token: AccountId,
    ) -> Option<OmniAddress> {
        self.token_id_to_address.get(&(chain_kind, token))
    }

    pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
        if let OmniAddress::Near(token_account_id) = address {
            token_account_id.clone()
        } else {
            self.token_address_to_id
                .get(address)
                .near_expect(BridgeError::TokenNotRegistered)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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
    }
```
