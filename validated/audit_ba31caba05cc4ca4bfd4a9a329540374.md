Audit Report

## Title
Removed Relayer Permanently Freezes Fee Tokens in `claim_fee()` - (File: near/omni-bridge/src/lib.rs)

## Summary

`claim_fee()` is gated by `#[trusted_relayer]`, while `claim_fee_callback()` independently enforces `fee_recipient == predecessor_account_id`. Once a trusted relayer calls `sign_transfer()`, their account is cryptographically committed as `fee_recipient` in the MPC-signed payload and the resulting destination-chain `FinTransfer` event. If the relayer is removed before calling `claim_fee()`, neither the removed relayer (fails `#[trusted_relayer]`) nor any other account (fails `fee_recipient == predecessor_account_id`) can claim the fee, permanently freezing the fee tokens inside the bridge contract.

## Finding Description

**Step 1 — `fee_recipient` is committed at `sign_transfer()` time.**

`sign_transfer()` accepts a caller-supplied `fee_recipient: Option<AccountId>` and embeds it verbatim into `TransferMessagePayload`, which is then keccak-hashed and signed by the MPC network: [1](#0-0) 

The resulting signature is submitted to the destination chain, which emits a `FinTransfer` event with `fee_recipient` baked in. This value is now immutable: re-signing the same `destination_nonce` would produce a duplicate that the destination chain's replay protection rejects.

**Step 2 — `sign_transfer_callback()` retains the `pending_transfers` entry when fee > 0.** [2](#0-1) 

The transfer message (and its locked fee tokens) remains in `pending_transfers` until `claim_fee_callback()` calls `remove_transfer_message()`.

**Step 3 — `claim_fee()` requires the caller to be a trusted relayer.** [3](#0-2) 

**Step 4 — `claim_fee_callback()` additionally requires `fee_recipient == predecessor_account_id`.** [4](#0-3) 

**Step 5 — Relayer removal has no guard for pending fee claims.**

`resign_trusted_relayer` and `reject_relayer_application` immediately strip the relayer from the trusted set with no check for outstanding `pending_transfers` entries: [5](#0-4) 

**Dead-lock analysis:**

After removal of relayer R:
- R calls `claim_fee()` → reverts at `#[trusted_relayer]` (R is no longer trusted).
- Any other trusted relayer T calls `claim_fee()` → passes `#[trusted_relayer]`, but `claim_fee_callback()` reverts because `fee_recipient (R) ≠ predecessor_account_id (T)`.
- A DAO account D calls `claim_fee()` → passes `#[trusted_relayer]` via `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)` configured at the impl level, but `claim_fee_callback()` still reverts because `fee_recipient (R) ≠ predecessor_account_id (D)`. [6](#0-5) 

`remove_transfer_message()` is only called inside `claim_fee_callback()`: [7](#0-6) 

No other code path removes the entry or recovers the fee tokens. The funds are permanently frozen without a contract upgrade.

## Impact Explanation

The fee portion of the user's bridged amount is locked inside the bridge contract's `pending_transfers` map indefinitely. This constitutes **permanent freezing of bridged funds** across any supported destination chain (EVM, Solana, Starknet, Bitcoin, Zcash), matching the Critical impact class. The frozen amount equals the relayer fee agreed upon at transfer initiation — a non-trivial fraction of the bridged principal.

## Likelihood Explanation

The vulnerability window spans destination-chain finality time (minutes for EVM, longer for Bitcoin/Zcash). A relayer can be removed voluntarily (`resign_trusted_relayer`) or forcibly (`reject_relayer_application` by DAO) at any point in this window. Any relayer exiting the system while holding pending fee claims triggers the freeze. No attacker capability is required; the scenario arises from normal operational churn.

## Recommendation

Decouple the trusted-relayer gate from fee collection. The `fee_recipient == predecessor_account_id` check in `claim_fee_callback()` already cryptographically authenticates the caller via the verified on-chain proof. The simplest fix is to remove `#[trusted_relayer]` from `claim_fee()` entirely, allowing the original `fee_recipient` (even if no longer a trusted relayer) to collect their earned fee. Alternatively, allow any trusted relayer to call `claim_fee()` and route the fee to the `fee_recipient` from the proof regardless of who the caller is.

## Proof of Concept

1. Trusted relayer R calls `sign_transfer(transfer_id, Some(R), fee)` — `fee_recipient = R` is embedded in the MPC-signed payload and emitted on the destination chain.
2. Destination chain finalizes the transfer; `FinTransfer` event with `fee_recipient = R` is recorded on-chain.
3. DAO calls `reject_relayer_application(R)` — R is removed from the trusted set.
4. R calls `claim_fee(proof)` — reverts: `#[trusted_relayer]` rejects R.
5. Another trusted relayer T calls `claim_fee(proof)` — reverts in `claim_fee_callback()`: `fee_recipient (R) ≠ predecessor_account_id (T)`.
6. DAO account D calls `claim_fee(proof)` — passes `#[trusted_relayer]` bypass, reverts in `claim_fee_callback()`: `fee_recipient (R) ≠ predecessor_account_id (D)`.
7. `pending_transfers[transfer_id]` is never removed; fee tokens are frozen permanently.

A localnet integration test can reproduce this by: (a) setting up a trusted relayer, (b) initiating a transfer with a non-zero fee, (c) calling `sign_transfer` with `fee_recipient = relayer`, (d) calling `reject_relayer_application`, then (e) asserting that both `claim_fee` calls from R and T revert and that `pending_transfers` still contains the entry.

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1083-1086)
```rust
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
