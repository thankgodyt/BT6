### Title
Fee tokens permanently frozen when `fee_recipient` is a contract unable to invoke `claim_fee` — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The NEAR Omni Bridge enforces that only the designated `fee_recipient` account can call `claim_fee`, and that caller must also be a registered trusted relayer. If the `fee_recipient` is a NEAR smart contract that is not a trusted relayer, or is an immutable contract incapable of invoking `claim_fee`, the fee portion of the transfer is permanently locked in `pending_transfers` with no admin recovery path.

### Finding Description
When a relayer calls `sign_transfer`, they supply an arbitrary `fee_recipient: Option<AccountId>`. This value is embedded in the MPC-signed `TransferMessagePayload` and later verified on the foreign chain. On the NEAR side, the transfer message (holding the full `amount` including the fee) remains in `pending_transfers` until `claim_fee` is successfully called.

`claim_fee` carries two independent access restrictions:

1. **`#[trusted_relayer]` gate** — only accounts registered as active trusted relayers (or holding `Role::DAO` / `Role::UnrestrictedRelayer`) may call the function at all.
2. **`fee_recipient == predecessor_account_id` check** — inside `claim_fee_callback`, the contract enforces that the caller is exactly the `fee_recipient` recorded in the proof.

```rust
// near/omni-bridge/src/lib.rs  line 1055-1063
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

```rust
// near/omni-bridge/src/lib.rs  lines 1083-1085
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

The transfer message is only removed from `pending_transfers` inside `claim_fee_callback` (line 1094) or inside `sign_transfer_callback` when the fee is zero (line 657). For any non-zero fee, the message — and the fee tokens it accounts for — stays locked until `claim_fee` succeeds.

There is no admin escape hatch, no timeout, and no alternative path to release the locked fee tokens.

### Impact Explanation
The fee tokens are a portion of the user's bridged assets that were burned or locked on NEAR at `init_transfer` time. If `claim_fee` can never be executed, those tokens are permanently frozen inside the bridge's `pending_transfers` map. No admin function exists to recover them. This constitutes a permanent, irrecoverable loss of bridged funds, matching the critical impact class.

### Likelihood Explanation
A relayer calling `sign_transfer` may legitimately set `fee_recipient` to a treasury multisig, a DAO contract, or any other NEAR smart contract that is not itself registered as a trusted relayer. Such contracts are common in production deployments. Because the `fee_recipient` value is embedded in the MPC-signed payload, it cannot be changed after signing. Once the foreign-chain finalization occurs and the transfer message is retained for fee collection, the only recovery path is `claim_fee` — which the fee_recipient contract cannot call.

### Recommendation
Remove the `#[trusted_relayer]` gate from `claim_fee` and allow any account to submit the proof, while keeping the `fee_recipient == predecessor_account_id` check — or, alternatively, allow any caller to trigger `claim_fee` and route the fee directly to the `fee_recipient` recorded in the proof (analogous to the external report's recommendation of allowing any account to invoke `claim`). Additionally, consider adding an admin-accessible recovery function for stuck transfer messages.

### Proof of Concept
1. Relayer calls `sign_transfer(transfer_id, fee_recipient = Some("treasury.dao.near"), fee = Some(fee))` where `treasury.dao.near` is a DAO contract not registered as a trusted relayer.
2. MPC signs the payload; the foreign chain finalizes the transfer, releasing `amount - fee` to the recipient.
3. `sign_transfer_callback` retains the transfer message because `fee.is_zero()` is false (line 656-658).
4. `treasury.dao.near` attempts to call `claim_fee` — the `#[trusted_relayer]` macro rejects the call because the DAO contract is not a registered relayer.
5. No other account can satisfy both `#[trusted_relayer]` AND `fee_recipient == predecessor_account_id` simultaneously.
6. The fee tokens remain locked in `pending_transfers` indefinitely with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-452)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L654-658)
```rust
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
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

**File:** near/omni-bridge/src/lib.rs (L1093-1095)
```rust

        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

```
