### Title
Users Cannot Self-Service Recover Locked Tokens from Pending Transfers — (`near/omni-bridge/src/lib.rs`)

### Summary

Every function that advances or finalizes a cross-chain transfer in the NEAR Omni Bridge is gated by the `#[trusted_relayer]` macro. A user who has locked tokens in `pending_transfers` has no self-service mechanism to cancel the transfer and recover their funds. If the trusted-relayer network becomes unavailable, bridged tokens are permanently frozen.

### Finding Description

When a NEAR user initiates an outbound transfer via `ft_transfer_call → init_transfer`, their tokens are locked inside the bridge contract and a `TransferMessage` is inserted into `pending_transfers`. [1](#0-0) 

The only functions that can advance or finalize this transfer are:

- `sign_transfer` — gated by `#[trusted_relayer]` [1](#0-0) 

- `fin_transfer` — gated by `#[trusted_relayer]` [2](#0-1) 

- `claim_fee` — gated by `#[trusted_relayer]` [3](#0-2) 

The `#[trusted_relayer]` block-level attribute on the `impl Contract` block enforces this restriction across all three entry points, with bypass only for `Role::DAO` and `Role::UnrestrictedRelayer`. [4](#0-3) 

There is no public function that allows the original sender to cancel a pending transfer and reclaim their tokens. The `storage_unregister(force: true)` path only refunds the caller's *available* storage balance — it does not touch the tokens locked in `pending_transfers`. [5](#0-4) 

The `remove_transfer_message` helper, which would release the locked tokens, is private and only called from within relayer-gated callbacks. [6](#0-5) 

For inbound transfers (EVM → NEAR), the same pattern applies: a user who has locked tokens on the EVM side cannot call `fin_transfer` on NEAR themselves to receive their tokens.

### Impact Explanation

If the trusted-relayer network becomes unavailable — even temporarily — every user with a pending outbound transfer has their tokens permanently frozen inside the bridge contract. There is no timeout, no user-initiated cancellation, and no DAO-free recovery path. This constitutes permanent freezing of bridged funds across NEAR and EVM flows.

### Likelihood Explanation

The trusted-relayer set is a small, permissioned group that must stake and be approved. A coordinated outage, a regulatory action, or a protocol-level pause that disables relayers while leaving user funds locked is a realistic operational scenario. The external report's analogous finding was accepted at Medium severity for the same class of risk.

### Recommendation

Add a time-locked self-service cancellation function, callable only by the original `transfer.owner`, that:
1. Verifies the caller matches the `owner` field stored in `TransferMessageStorage`.
2. Enforces a minimum waiting period (e.g., 24–72 hours) to prevent griefing of in-flight relayer operations.
3. Calls `remove_transfer_message` to release storage and returns the locked tokens to the sender via `ft_transfer`.

This mirrors the recommendation in the external report: if a refund/cancellation is already attributable to a specific user, that user should be able to claim it without privileged intermediary intervention.

### Proof of Concept

1. User calls `ft_transfer_call` on a NEP-141 token with `msg` encoding an `InitTransfer` to an EVM recipient. Tokens are transferred to the bridge and `init_transfer_internal` inserts a `TransferMessage` into `pending_transfers`. [7](#0-6) 

2. All trusted relayers go offline (or the bridge is paused for relayers while DAO bypass is unavailable).

3. The user attempts to call `sign_transfer` directly. The `#[trusted_relayer]` guard rejects the call — confirmed by the existing integration test `test_untrusted_sender_cannot_sign_transfer`. [1](#0-0) 

4. The user calls `storage_unregister(force: true)`. They receive only their `available` balance plus `required_balance_for_account`. The tokens locked in `pending_transfers` are not returned. [8](#0-7) 

5. The user has no further recourse. Their bridged tokens remain permanently locked in the contract with no on-chain recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L670-673)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1054-1057)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
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

**File:** near/omni-bridge/src/storage.rs (L214-236)
```rust
    #[payable]
    pub fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let Some(storage) = self.storage_balance_of(&account_id) else {
            return false;
        };

        if !force.unwrap_or_default() {
            require!(
                storage.total.saturating_sub(storage.available)
                    == self.required_balance_for_account(),
                BridgeError::StoragePendingTransfers.as_ref()
            );
        }

        self.accounts_balances.remove(&account_id);

        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
        true
```
