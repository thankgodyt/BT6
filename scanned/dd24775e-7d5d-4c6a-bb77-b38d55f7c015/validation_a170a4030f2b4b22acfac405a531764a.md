### Title
Token Migration Deletes Pending-Transfer Key, Permanently Locking Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`migrate_deployed_token` removes the `token_id_to_address` mapping for `old_token` without checking for in-flight transfers that still reference it. Any pending outbound transfer whose stored token ID is `old_token` can never be signed afterward, permanently locking the user's bridged funds inside the contract.

---

### Finding Description

When the DAO calls `migrate_deployed_token(origin_chain, old_token, new_token)`, the function removes the forward mapping and inserts a new one:

```rust
let origin_address = self
    .token_id_to_address
    .remove(&(origin_chain, old_token.clone()))   // ← key deleted
    .near_expect(BridgeError::FailedToGetTokenAddress);

self.token_id_to_address
    .insert(&(origin_chain, new_token.clone()), &origin_address);

self.token_address_to_id
    .insert(&origin_address, &new_token)           // ← reverse now points to new_token
    .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);
``` [1](#0-0) 

After this call, `token_id_to_address[(origin_chain, old_token)]` no longer exists.

Every pending outbound transfer created before the migration stores `token = OmniAddress::Near(old_token)` in `pending_transfers`. When `sign_transfer` is later called for such a transfer, it executes:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),   // == origin_chain
        self.get_token_id(&transfer_message.token), // == old_token
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [2](#0-1) 

`get_token_address` performs a direct lookup:

```rust
pub fn get_token_address(&self, chain_kind: ChainKind, token: AccountId) -> Option<OmniAddress> {
    self.token_id_to_address.get(&(chain_kind, token))
}
``` [3](#0-2) 

Because the key was deleted, this returns `None`, and `sign_transfer` panics unconditionally. The same panic occurs in `claim_fee_callback`, which performs an identical lookup:

```rust
let token = self.get_token_id(&transfer_message.token);
let token_address = self
    .get_token_address(transfer_message.get_destination_chain(), token.clone())
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [4](#0-3) 

The `swap_migrated_token` recovery path (reachable via `ft_on_transfer`) only helps users who still hold old tokens in their wallets; it cannot help users whose tokens were already transferred into the bridge as part of a pending transfer. [5](#0-4) 

There is no cancel-transfer or forced-refund function in the contract, so the locked tokens have no recovery path short of a contract upgrade.

---

### Impact Explanation

A user who initiates an outbound transfer (NEAR → foreign chain) has their tokens transferred into the bridge contract and stored in `pending_transfers`. If the DAO migrates the underlying token before `sign_transfer` is called, the MPC signing step can never succeed. The user's tokens remain permanently locked inside the bridge with no on-chain mechanism to retrieve them. This constitutes permanent freezing of bridged funds.

---

### Likelihood Explanation

The DAO must call `migrate_deployed_token` while at least one pending transfer for `old_token` targeting the same `origin_chain` exists. Token migrations are infrequent but realistic (e.g., upgrading a broken token contract). During high-activity periods, pending transfers are almost always present. The DAO has no on-chain guard preventing migration while transfers are in flight, making this an easy mistake to make during an urgent migration.

---

### Recommendation

Before deleting the old mapping in `migrate_deployed_token`, assert that no pending transfers reference `old_token` on `origin_chain`, or alternatively update the stored `token` field of all affected pending transfers to `OmniAddress::Near(new_token)` as part of the migration. A simpler mitigation is to add a `pending_transfer_count` per token and require it to be zero before migration proceeds.

---

### Proof of Concept

1. User calls `ft_transfer_call` on `old_token` contract → bridge stores `TransferMessage { token: OmniAddress::Near(old_token), ... }` in `pending_transfers`. [6](#0-5) 

2. DAO calls `migrate_deployed_token(ChainKind::Eth, old_token, new_token)` → `token_id_to_address[(Eth, old_token)]` is deleted. [7](#0-6) 

3. Relayer (or user) calls `sign_transfer` for the pending transfer → `get_token_address(Eth, old_token)` returns `None` → `env::panic_str("ERR_FAILED_TO_GET_TOKEN_ADDRESS")`. [2](#0-1) 

4. No other public function can sign or cancel the transfer. The user's tokens are permanently locked in the bridge contract.

### Citations

**File:** near/omni-bridge/src/lib.rs (L275-279)
```rust
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
```

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

**File:** near/omni-bridge/src/lib.rs (L540-553)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1115-1120)
```rust
        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });
```

**File:** near/omni-bridge/src/lib.rs (L1360-1366)
```rust
    pub fn get_token_address(
        &self,
        chain_kind: ChainKind,
        token: AccountId,
    ) -> Option<OmniAddress> {
        self.token_id_to_address.get(&(chain_kind, token))
    }
```

**File:** near/omni-bridge/src/lib.rs (L1628-1642)
```rust
        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);
```
