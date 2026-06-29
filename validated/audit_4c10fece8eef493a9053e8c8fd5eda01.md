Looking at the NEAR Omni Bridge codebase, I need to find an analog to the vulnerability class: **a state change between the two legs of a cross-chain operation causes the second leg to fail, resulting in permanent fund loss**.

Let me trace the NEAR→EVM transfer lifecycle and the `migrate_deployed_token` admin function.

**Key code paths:**

`sign_transfer` (the second leg for NEAR→EVM): [1](#0-0) 

`migrate_deployed_token` (DAO function that removes the old token mapping): [2](#0-1) 

`init_transfer_internal` (burns tokens at initiation, before any state check on destination): [3](#0-2) 

`get_token_address` (the lookup that fails after migration): [4](#0-3) 

---

### Title
In-flight NEAR→EVM Transfers Permanently Frozen After `migrate_deployed_token` Removes Old Token Mapping - (File: `near/omni-bridge/src/lib.rs`)

### Summary
When the DAO calls `migrate_deployed_token` to replace an old deployed token with a new one, any NEAR→EVM transfers already stored in `pending_transfers` for the old token become permanently unfinalizeable. `sign_transfer` panics because the old token's address mapping is deleted, while the user's tokens have already been irreversibly burned on NEAR with no cancel or ref

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
