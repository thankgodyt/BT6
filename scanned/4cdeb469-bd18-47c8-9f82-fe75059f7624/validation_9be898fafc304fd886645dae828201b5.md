### Title
Relayer Removal After `sign_transfer()` Permanently Freezes Fee Tokens in `claim_fee()` - (File: near/omni-bridge/src/lib.rs)

### Summary

The `claim_fee()` function enforces a `#[trusted_relayer]` check at fee-claim time. Once a relayer calls `sign_transfer()`, their account is permanently baked as `fee_recipient` into the on-chain destination-chain event. If the relayer is removed (via `resign_trusted_relayer` or `reject_relayer_application`) before they call `claim_fee()`, the fee tokens are permanently frozen: the removed relayer cannot call `claim_fee()` (not trusted), and no other relayer can claim the fee because `claim_fee_callback()` enforces `fee_recipient == predecessor_account_id`.

### Finding Description

The bridge's outbound fee-claim flow works as follows:

1. A trusted relayer calls `sign_transfer()`, passing themselves as `fee_recipient`. This constructs a `TransferMessagePayload` containing `fee_recipient` and requests an MPC signature.
2. The MPC signature is used on the destination chain to release tokens. The destination chain emits a `FinTransfer` event with `fee_recipient` embedded.
3. The relayer calls `claim_fee()` with a proof of that event. `claim_fee_callback()` verifies `fee_recipient == predecessor_account_id` and pays the fee.

The vulnerability arises between steps 1 and 3. `claim_fee()` is decorated with `#[trusted_relayer]`: [1](#0-0) 

And `claim_fee_callback()` enforces that only the exact `fee_recipient` from the proof can collect: [2](#0-1) 

If the relayer is removed between `sign_transfer()` and `claim_fee()`:
- The removed relayer fails the `#[trusted_relayer]` check in `claim_fee()`.
- Any other trusted relayer fails the `fee_recipient == predecessor_account_id` check in `claim_fee_callback()`.
- The `pending_transfers` entry is never removed (it is only removed inside `claim_fee_callback()`).
- The fee tokens remain locked in the bridge contract indefinitely.

The `fee_recipient` is immutable after `sign_transfer()` because it is baked into the destination-chain event. Calling `sign_transfer()` again for the same transfer would produce a new MPC signature for the same destination nonce, which the destination chain would reject (replay protection). [3](#0-2) 

The `#[trusted_relayer]` macro is configured with bypass roles `DAO` and `UnrestrictedRelayer`, but a removed relayer holds neither role, so no bypass is available. [4](#0-3) 

### Impact Explanation

Fee tokens (a portion of the user's original bridged amount) are permanently frozen inside the bridge contract. The `pending_transfers` entry for the transfer is never removed, and the fee is never distributed. This constitutes permanent freezing of bridged funds across any supported destination chain (EVM, Solana, Starknet, Bitcoin, Zcash).

### Likelihood Explanation

The window between `sign_transfer()` and `claim_fee()` spans destination-chain finality time (minutes to hours for EVM, longer for Bitcoin). A relayer can be removed voluntarily (`resign_trusted_relayer`) or forcibly (`reject_relayer_application` by DAO) at any time during this window. The scenario is realistic whenever a relayer exits the system while having pending fee claims. [5](#0-4) 

### Recommendation

Decouple the trusted-relayer check from `claim_fee()`. Options:
1. Remove the `#[trusted_relayer]` guard from `claim_fee()` and rely solely on the `fee_recipient == predecessor_account_id` proof check, which already authenticates the caller.
2. Allow any trusted relayer to call `claim_fee()` and route the fee to the `fee_recipient` from the proof, regardless of who the caller is.
3. Before removing a relayer, check for and settle any pending fee claims associated with that relayer.

### Proof of Concept

1. Trusted relayer R calls `sign_transfer(transfer_id, Some(R), fee)` — `fee_recipient = R` is baked into the MPC-signed payload and emitted on the destination chain.
2. DAO calls `reject_relayer_application(R)` — R is removed from the trusted set.
3. R attempts `claim_fee(proof)` — reverts because `#[trusted_relayer]` rejects R.
4. Another trusted relayer T attempts `claim_fee(proof)` — reverts in `claim_fee_callback()` because `fee_recipient (R) != predecessor_account_id (T)`.
5. The transfer message remains in `pending_transfers` forever; fee tokens are frozen. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L491-500)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1054-1064)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1079-1086)
```rust
        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-tests/src/relayer_staking.rs (L338-344)
```rust
        // Resign
        applicant
            .call(env.bridge_contract.id(), "resign_trusted_relayer")
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```
