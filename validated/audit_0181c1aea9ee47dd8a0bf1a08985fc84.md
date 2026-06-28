### Title
Silent `fee_recipient.parse().ok()` in Wormhole `TryInto<FinTransferMessage>` Causes Permanent `pending_transfer` Freeze via `claim_fee_callback` Panic — (`near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs`)

---

### Summary

When the Wormhole prover proxy decodes a `FinTransfer` VAA, it silently converts an unparseable `fee_recipient` string to `None` via `.parse().ok()`. The downstream `claim_fee_callback` then panics unconditionally on `None`, but the panic fires **before** `remove_transfer_message` is called, leaving the `pending_transfer` permanently in state with no admin escape hatch.

---

### Finding Description

**Step 1 — Silent `None` production in the prover proxy**

In `TryInto<FinTransferMessage> for ParsedVAA`:

```rust
// near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs
Ok(FinTransferMessage {
    transfer_id: transfer.transfer_id,
    fee_recipient: transfer.fee_recipient.parse().ok(),   // ← silently None on any parse failure
    amount: transfer.amount.into(),
    emitter_address: ...,
})
``` [1](#0-0) 

The raw `fee_recipient` field is a `String` Borsh-decoded from the VAA payload. Any value that fails `AccountId::from_str` — empty string, string with invalid characters, string exceeding 64 bytes — silently becomes `None`. No error is returned; `verify_vaa_callback` returns `Ok(ProverResult::FinTransfer(...))` with `fee_recipient: None`. [2](#0-1) 

**Step 2 — Unconditional panic in `claim_fee_callback` before state cleanup**

```rust
// near/omni-bridge/src/lib.rs
let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
    env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
});
// ...
let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id); // ← never reached
``` [3](#0-2) 

The panic at line 1080 fires **before** `remove_transfer_message` at line 1094. NEAR's receipt model reverts only the callback's own state changes; the `pending_transfer` entry was already committed in a prior receipt and is not touched by this panic. It remains in `pending_transfers` indefinitely.

**Step 3 — No recovery path exists**

There is no DAO/admin function to force-remove a `pending_transfer`. The only removal paths are `remove_transfer_message` (inside `claim_fee_callback`, unreachable after the panic) and `remove_fin_transfer` (inside `fin_transfer_send_tokens_callback`, a different flow). The Wormhole prover proxy does not track used VAAs, so the same VAA can be re-submitted, but it will always produce `fee_recipient: None` and always panic. [4](#0-3) 

The same silent `.parse().ok()` pattern appears in the EVM event parser for `FinTransfer`: [5](#0-4) 

---

### Impact Explanation

When the `pending_transfer` cannot be removed:

1. **Storage deposit frozen**: The transfer initiator's storage deposit (credited to `accounts_balances`) is never refunded via `remove_transfer_message`'s storage-cost accounting. Those NEAR tokens are permanently locked in the bridge contract.
2. **`locked_tokens` counter not decremented**: `send_fee_internal` (which decrements `locked_tokens`) is never reached, leaving the accounting counter permanently inflated for that `(chain, token)` pair.
3. **Relayer fee permanently lost**: The relayer cannot claim their fee for the finalized transfer.

---

### Likelihood Explanation

The precondition is that a Wormhole-signed VAA reaches `claim_fee` with an invalid `fee_recipient` string. This can occur via:

- A relayer software bug that encodes an empty or malformed NEAR account ID as `fee_recipient` in the source-chain `FinTransfer` call.
- A source-chain contract (Solana/BNB/L2) that permits any caller to supply an arbitrary `fee_recipient` when finalizing a transfer, allowing a third party to set `fee_recipient = ""` before the legitimate relayer acts.

The `#[trusted_relayer]` gate on `claim_fee` means the submitter must be a staked, auto-promoted relayer — but the relayer staking system is permissionless (anyone can apply and be auto-promoted after a waiting period). [6](#0-5) 

---

### Recommendation

Replace the silent `.parse().ok()` with a hard error in both the Wormhole and EVM `FinTransferMessage` parsers:

```rust
fee_recipient: if transfer.fee_recipient.is_empty() {
    None
} else {
    Some(transfer.fee_recipient.parse().map_err(stringify)?)
},
```

Additionally, `claim_fee_callback` should return an `Err` (not panic) when `fee_recipient` is `None`, so the callback fails gracefully without leaving the `pending_transfer` stranded. A DAO-gated `force_remove_pending_transfer` escape hatch would also mitigate any future stuck entries.

---

### Proof of Concept

**Unit test** (`parsed_vaa.rs`): construct a `FinTransferWh` with `fee_recipient = ""`, Borsh-encode it as a fake VAA payload, call `TryInto<FinTransferMessage>`, assert `fee_recipient == None`.

**Integration test** (`claim_fee_callback`): insert a `pending_transfer` into state, call `claim_fee_callback` with `ProverResult::FinTransfer(FinTransferMessage { fee_recipient: None, .. })`, assert the call panics with `FeeRecipientNotSetOrEmpty`, then assert `get_transfer_message` still returns the entry (i.e., it was not removed). [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L134-141)
```rust
#[derive(Debug, BorshDeserialize)]
struct FinTransferWh {
    payload_type: ProofKind,
    transfer_id: TransferId,
    token_address: OmniAddress,
    amount: u128,
    fee_recipient: String,
}
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L185-205)
```rust
impl TryInto<FinTransferMessage> for ParsedVAA {
    type Error = String;

    fn try_into(self) -> Result<FinTransferMessage, String> {
        let transfer: FinTransferWh = borsh::from_slice(&self.payload).map_err(stringify)?;

        if transfer.payload_type != ProofKind::FinTransfer {
            return Err("Invalid proof kind".to_owned());
        }

        Ok(FinTransferMessage {
            transfer_id: transfer.transfer_id,
            fee_recipient: transfer.fee_recipient.parse().ok(),
            amount: transfer.amount.into(),
            emitter_address: OmniAddress::new_from_slice(
                transfer.token_address.get_chain(),
                &self.emitter_address,
            )?,
        })
    }
}
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

**File:** near/omni-types/src/evm/events.rs (L96-113)
```rust
impl TryFromLog<Log<FinTransfer>> for FinTransferMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<FinTransfer>) -> Result<Self, Self::Error> {
        Ok(Self {
            transfer_id: crate::TransferId {
                origin_chain: event.data.originChain.try_into()?,
                origin_nonce: event.data.originNonce,
            },
            amount: near_sdk::json_types::U128(event.data.amount),
            fee_recipient: event.data.feeRecipient.parse().ok(),
            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
        })
    }
}
```
