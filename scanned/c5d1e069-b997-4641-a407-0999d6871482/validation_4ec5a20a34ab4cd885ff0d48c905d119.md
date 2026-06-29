### Title
Factory Address Update Without Draining In-Flight Transfers Permanently Freezes Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When the DAO updates the registered factory address for a chain (e.g., after an EVM bridge contract upgrade), any in-flight Foreign→NEAR transfers whose proof carries the old factory's `emitter_address` will permanently fail finalization. Users who already locked tokens on the foreign chain cannot receive their tokens on NEAR, and the locked funds are permanently frozen.

---

### Finding Description

The `Contract` struct maintains a `factories: LookupMap<ChainKind, OmniAddress>` — a **single** factory address per chain. [1](#0-0) 

Every inbound finalization (`fin_transfer_callback`) hard-requires that the proof's `emitter_address` exactly matches the **currently** registered factory for that chain: [2](#0-1) 

Similarly, every outbound fee claim (`claim_fee_callback`) performs the same check: [3](#0-2) 

The DAO can overwrite the factory address for a chain at any time (the `factories.insert` call in `lib.rs` is the only write path). There is **no mechanism** to:

- Drain or finalize pending in-flight transfers before the factory address is replaced.
- Maintain a set of historically valid factory addresses so that old proofs remain acceptable.
- Refund users whose transfers can no longer be finalized.

**Attack / Failure Scenario (Foreign → NEAR):**

1. User locks tokens on the EVM bridge (old factory contract). The lock event is emitted by `old_factory_address`.
2. Before the relayer submits the finalization proof to NEAR, the DAO upgrades the EVM bridge to a new contract address and calls the factory-update function, replacing `old_factory_address` with `new_factory_address` in `self.factories`.
3. The relayer submits the proof (which carries `emitter_address = old_factory_address`) to `fin_transfer`.
4. `fin_transfer_callback` evaluates `self.factories.get(&chain) == Some(old_factory_address)` → **false** (now `new_factory_address` is stored). The call panics with `ERR_UNKNOWN_FACTORY`.
5. The transfer is never stored in `finalised_transfers`, so the relayer can retry indefinitely — but every attempt will fail for the same reason.
6. The user's tokens are permanently frozen in the old EVM factory contract with no recovery path on NEAR.

**Attack / Failure Scenario (NEAR → Foreign, fee loss):**

1. User initiates a NEAR→Foreign transfer; tokens are burned/locked on NEAR and the transfer is stored in `pending_transfers`.
2. The DAO updates the factory address.
3. The relayer submits the foreign-chain finalization proof to `claim_fee`. `claim_fee_callback` fails the factory check.
4. The transfer stays in `pending_transfers` indefinitely; the fee portion of locked tokens is never unlocked via `unlock_tokens_if_needed`. [4](#0-3) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

For Foreign→NEAR transfers, users who locked tokens on the foreign chain before the factory update have no on-chain path to receive their tokens on NEAR. The `finalised_transfers` set never records the transfer, so replay protection does not help; the root cause is the factory mismatch, not a replay. Funds are permanently frozen.

For NEAR→Foreign transfers, the fee portion of locked native tokens is permanently stuck in the bridge contract, and the relayer loses their earned fee.

---

### Likelihood Explanation

Factory address updates are a routine operational event: any EVM bridge contract upgrade, redeployment, or chain migration requires the DAO to call the factory-update function. The DAO has no on-chain tooling to check whether in-flight transfers exist before overwriting the factory. Given that cross-chain transfers can take minutes to hours to finalize (waiting for block confirmations, relayer scheduling, governance delays), the window for in-flight transfers to be affected is realistic and non-trivial.

---

### Recommendation

1. **Maintain a set of accepted factory addresses per chain** instead of a single address. Old factory addresses should remain valid for finalizing transfers until explicitly retired, and retirement should only be allowed when no pending transfers reference that factory.

2. **Add a grace-period or two-step factory rotation**: stage the new factory address, allow a configurable delay during which old-factory proofs are still accepted, then finalize the rotation.

3. **Provide an emergency withdrawal path**: if a factory address is rotated and a transfer cannot be finalized, allow the DAO (or the original sender) to cancel the pending transfer and refund the user's tokens.

---

### Proof of Concept

```
State before update:
  factories[Eth] = 0xOLD_FACTORY

User action:
  EVM: lock 1000 USDC in 0xOLD_FACTORY  →  emits InitTransfer(nonce=42, emitter=0xOLD_FACTORY)

DAO action (before relayer finalizes):
  NEAR: add_factory(Eth, 0xNEW_FACTORY)
  → factories[Eth] = 0xNEW_FACTORY  (0xOLD_FACTORY is gone)

Relayer action:
  NEAR: fin_transfer(proof{ emitter_address: 0xOLD_FACTORY, origin_nonce: 42, ... })
  → fin_transfer_callback:
      self.factories.get(Eth) == Some(0xNEW_FACTORY)
      0xNEW_FACTORY != 0xOLD_FACTORY  →  panic!("ERR_UNKNOWN_FACTORY")

Result:
  - Transfer never stored in finalised_transfers
  - User's 1000 USDC permanently locked in 0xOLD_FACTORY on EVM
  - No recovery path exists on NEAR
``` [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L221-221)
```rust
    pub factories: LookupMap<ChainKind, OmniAddress>,
```

**File:** near/omni-bridge/src/lib.rs (L700-713)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1066-1092)
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
```

**File:** near/omni-bridge/src/lib.rs (L2684-2684)
```rust
        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);
```
