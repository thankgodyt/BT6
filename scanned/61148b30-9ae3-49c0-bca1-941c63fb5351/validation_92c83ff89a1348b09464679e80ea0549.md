### Title
Fee Tokens Permanently Locked When `fee_recipient` Relayer Is Revoked Before Calling `claim_fee` - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee` enforces two independent caller restrictions: the `#[trusted_relayer]` attribute and an explicit `fee_recipient == predecessor_account_id` check. If the relayer that was designated as `fee_recipient` during `sign_transfer` is subsequently revoked by the DAO, neither they nor any other account can ever call `claim_fee` for that transfer. The fee portion of the transfer is permanently locked inside `pending_transfers` and the `locked_tokens` accounting counter is never decremented.

### Finding Description

The NEAR→Foreign transfer flow works as follows:

1. A user calls `ft_transfer_call` → `init_transfer`, locking the full token amount (including fee) in the bridge contract and storing a `TransferMessage` in `pending_transfers`.
2. A trusted relayer calls `sign_transfer(transfer_id, fee_recipient=relayer_account, fee=...)`. The `fee_recipient` is embedded into the MPC-signed `TransferMessagePayload` and broadcast to the destination chain.
3. The destination chain finalizes the transfer, releasing `amount - fee` to the user. The fee portion remains locked on NEAR.
4. The relayer must call `claim_fee` on NEAR with a proof from the destination chain to collect the fee and remove the `TransferMessage` from `pending_transfers`.

`claim_fee` carries two hard caller restrictions:

```rust
// Restriction 1: caller must be a currently-active trusted relayer
#[trusted_relayer]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }
```

```rust
// Restriction 2: caller must be exactly the fee_recipient embedded in the proof
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

The `fee_recipient` is fixed at `sign_transfer` time and is cryptographically bound into the MPC signature; it cannot be changed after the fact.

If the DAO revokes the relayer (via `reject_relayer_application`) between steps 2 and 4:
- The revoked relayer fails restriction 1 (`#[trusted_relayer]`) and cannot call `claim_fee`.
- No other trusted relayer can satisfy restriction 2 (`fee_recipient == predecessor_account_id`).
- The DAO itself has `bypass_roles` for the `#[trusted_relayer]` check, but still fails restriction 2 because the DAO account is not the `fee_recipient`.
- There is no admin rescue function to remove a stuck `TransferMessage` or force-decrement `locked_tokens`.

Result: the `TransferMessage` remains in `pending_transfers` indefinitely, the fee tokens are permanently locked in the bridge contract, and `locked_tokens` is never decremented for the fee amount.

### Impact Explanation

The fee portion of every affected NEAR→Foreign transfer is permanently frozen inside the bridge contract. The `locked_tokens` counter retains a stale inflated value, causing a permanent discrepancy between the bridge's accounting and its actual spendable balance. This is a permanent loss of bridged funds and a balance mis-accounting, both of which fall within the critical impact scope.

### Likelihood Explanation

The DAO legitimately revokes relayers for misbehavior. Any relayer that has signed one or more transfers with a non-zero fee and has not yet called `claim_fee` will have those fees permanently locked the moment the DAO revokes them. A relayer could also resign voluntarily (`resign_trusted_relayer`) and then be unable to call `claim_fee`. The scenario requires no attacker — it is a natural consequence of normal protocol administration.

### Recommendation

Remove the `#[trusted_relayer]` guard from `claim_fee` (or add a bypass for the specific `fee_recipient` account regardless of their current relayer status), so that the designated `fee_recipient` can always claim their earned fee even after losing trusted-relayer status. Alternatively, allow the DAO to administratively clear a stuck `pending_transfers` entry and return the fee to a configurable rescue address.

### Proof of Concept

1. User initiates a NEAR→Eth transfer with `fee = 1000` tokens. `pending_transfers` now holds the `TransferMessage` with `amount = 10000`, `fee.fee = 1000`.
2. Trusted relayer `relayer.near` calls `sign_transfer(transfer_id, fee_recipient="relayer.near", fee=...)`. MPC signature is produced; destination chain finalizes, sending `9000` tokens to the user.
3. DAO calls `reject_relayer_application("relayer.near")`. `relayer.near` is no longer a trusted relayer.
4. `relayer.near` attempts `claim_fee(...)` → panics at the `#[trusted_relayer]` guard: "Relayer is not active".
5. Any other trusted relayer attempts `claim_fee(...)` → panics at `BridgeError::OnlyFeeRecipientCanClaim` because `fee_recipient ("relayer.near") != predecessor_account_id`.
6. The `TransferMessage` with `fee = 1000` tokens remains in `pending_transfers` forever. `locked_tokens` for the destination chain is never decremented by the fee amount.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
