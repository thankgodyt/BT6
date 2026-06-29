### Title
Unresponsive Fee-Recipient Relayer Permanently Freezes Fee Tokens in Bridge — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee` is the sole mechanism for removing a `TransferMessage` from `pending_transfers` when a fee is non-zero. It enforces two independent restrictions: the caller must be a `#[trusted_relayer]` **and** must equal the `fee_recipient` embedded in the on-chain proof. If the specific relayer who was named as `fee_recipient` becomes unresponsive, no other party can ever advance the state, permanently freezing the fee tokens inside the bridge contract.

### Finding Description

The NEAR → Foreign-chain transfer flow stores a `TransferMessage` in `pending_transfers` when `init_transfer` is called. For transfers with a non-zero fee, the message is only removed when `claim_fee` succeeds. The callback enforces:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
``` [1](#0-0) 

Combined with the outer `#[trusted_relayer]` guard on `claim_fee`: [2](#0-1) 

The `fee_recipient` is chosen by whoever calls `sign_transfer` and is baked into the MPC-signed payload and the on-chain proof. Once the proof is submitted, only the account whose identity matches `fee_recipient` in that proof can call `claim_fee`. No other trusted relayer, no DAO action, and no admin function can substitute.

`sign_transfer_callback` only removes the transfer message when the fee is zero:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
``` [3](#0-2) 

There is no other code path that removes a non-zero-fee `TransferMessage` from `pending_transfers`: [4](#0-3) 

### Impact Explanation

When the fee-recipient relayer becomes unresponsive:

1. The `TransferMessage` remains in `pending_transfers` indefinitely with no recovery path.
2. The fee tokens (deducted from the user's transfer amount and held in the bridge) are permanently frozen. For non-deployed tokens the fee amount stays locked; for deployed tokens it was burned and is irrecoverable.
3. The `locked_tokens` accounting for the destination chain is never decremented by the fee amount, silently inflating the bridge's internal bookkeeping.
4. The storage deposit paid by the transfer owner is also permanently locked.

This constitutes permanent freezing of bridged funds, satisfying the critical impact criterion.

### Likelihood Explanation

A trusted relayer calls `sign_transfer`, naming itself as `fee_recipient`. The MPC signature is produced and the destination chain finalizes the transfer. Before the relayer calls `claim_fee` on NEAR it loses access to its key (hardware failure, key loss, operator shutdown). Because the `fee_recipient` identity is fixed in the already-submitted proof, no substitute caller exists. This scenario requires no adversarial action — ordinary operational failure suffices.

### Recommendation

Remove the `fee_recipient == predecessor_account_id` restriction from `claim_fee_callback`, or allow any trusted relayer to call `claim_fee` on behalf of the named `fee_recipient` (paying the fee out to the `fee_recipient` address regardless of who submits the proof). This mirrors the fix applied in Audius PR #556: make the state-advancing function callable by any eligible party, not only the original designated party.

### Proof of Concept

1. Alice (trusted relayer) calls `sign_transfer(transfer_id, fee_recipient=Some(alice), fee=Some(fee))`.
2. MPC produces a signature; `SignTransferEvent` is emitted. Because `fee > 0`, `sign_transfer_callback` does **not** remove the `TransferMessage`.
3. The destination chain finalizes the transfer; a `FinTransfer` proof is produced with `fee_recipient = alice`.
4. Alice loses her private key and can never submit a transaction again.
5. Any other trusted relayer calls `claim_fee` with the proof. `claim_fee_callback` executes:
   ```
   require!(fee_recipient == *predecessor_account_id, ...)
   // fee_recipient = alice, predecessor = bob → PANIC
   ```
6. The call reverts. The `TransferMessage` remains in `pending_transfers` forever. The fee tokens are permanently frozen in the bridge with no admin escape hatch. [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1054-1057)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1066-1094)
```rust
    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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
