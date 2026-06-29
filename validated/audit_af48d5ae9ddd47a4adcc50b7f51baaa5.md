Audit Report

## Title
Permanent Freezing of Bridge Fees Due to Conflicting Access Controls on `claim_fee` — (`near/omni-bridge/src/lib.rs`)

## Summary

`claim_fee` is gated by `#[trusted_relayer]`, but `claim_fee_callback` additionally requires `fee_recipient == predecessor_account_id`. Because `sign_transfer` accepts an arbitrary `fee_recipient: Option<AccountId>` that is embedded in the MPC-signed payload, any configuration where the `fee_recipient` is not simultaneously a trusted relayer makes the fee permanently unclaimable. The `pending_transfers` entry and `locked_tokens` accounting are never cleaned up, permanently freezing the fee tokens inside the bridge.

## Finding Description

`sign_transfer` accepts an arbitrary `fee_recipient` and embeds it in the MPC-signed `TransferMessagePayload`:

```rust
// near/omni-bridge/src/lib.rs L447-500
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,  // arbitrary AccountId
    fee: &Option<Fee>,
) -> Promise {
    ...
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,  // embedded in MPC-signed payload
        ...
    };
```

`claim_fee` is gated by `#[trusted_relayer]`:

```rust
// near/omni-bridge/src/lib.rs L1054-1064
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }
```

`claim_fee_callback` then enforces that the caller **is** the `fee_recipient` from the proof:

```rust
// near/omni-bridge/src/lib.rs L1083-1086
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

These two checks are mutually exclusive when `fee_recipient` is not a trusted relayer:
- `fee_recipient` (e.g., `treasury.near`) cannot pass the `#[trusted_relayer]` guard at L1055.
- Any trusted relayer who calls `claim_fee` passes the guard but fails the `fee_recipient == predecessor_account_id` check at L1084.

The `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)` configured on the `#[trusted_relayer]` macro at L245-249 does not resolve this: even if DAO calls `claim_fee`, it still fails the `fee_recipient == predecessor_account_id` check in the callback unless DAO is also the designated `fee_recipient`.

Because `remove_transfer_message` (L1094) and `unlock_tokens_if_needed` via `send_fee_internal` (L2684) are only reachable through a successful `claim_fee_callback`, the `pending_transfers` entry and `locked_tokens` accounting are never cleaned up.

## Impact Explanation

This causes **permanent freezing of bridged funds** — specifically the fee portion of bridged assets locked in `pending_transfers`. The `locked_tokens` map is never decremented via `unlock_tokens_if_needed`, and no unprivileged party can recover the tokens. This matches the Critical impact class: *permanent freezing of bridged funds across NEAR, EVM, or other supported chains*.

## Likelihood Explanation

Two realistic, non-adversarial paths trigger this:

1. **Treasury fee collection**: A trusted relayer sets `fee_recipient` to a separate treasury/multisig account (not registered as a trusted relayer). This is a standard operational pattern for fee accounting.
2. **Relayer revocation**: A trusted relayer sets `fee_recipient` to themselves, but the DAO later calls `reject_relayer_application`, revoking their trusted status. After revocation, the former relayer cannot pass `#[trusted_relayer]`, and no other trusted relayer can satisfy `fee_recipient == predecessor_account_id`. The revocation path is confirmed by the existing test at `near/omni-tests/src/relayer_staking.rs` L467-488.

Neither path requires attacker action — normal operational behavior is sufficient to trigger permanent fund freezing.

## Recommendation

Remove the `#[trusted_relayer]` guard from `claim_fee`. The `claim_fee_callback` check `fee_recipient == predecessor_account_id` is the correct and sufficient access control — only the designated fee recipient should be able to claim. The trusted-relayer guard is redundant for security and actively harmful for liveness.

```rust
// Before
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }

// After
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }
```

## Proof of Concept

1. DAO configures a trusted relayer (`applicant`) with a stake.
2. A user calls `ft_transfer_call` → `init_transfer` on NEAR, locking tokens destined for Ethereum with a non-zero fee.
3. `applicant` calls `sign_transfer` with `fee_recipient = Some("treasury.near")` where `treasury.near` is **not** a trusted relayer.
4. MPC signs the payload; the relayer submits the signed transaction to Ethereum; Ethereum emits a `FinTransfer` event with `fee_recipient = "treasury.near"`.
5. `treasury.near` calls `claim_fee` with the Ethereum proof → **panics** at the `#[trusted_relayer]` guard (L1055).
6. `applicant` calls `claim_fee` with the same proof → passes `#[trusted_relayer]` but **panics** at `require!(fee_recipient == *predecessor_account_id)` (L1084) because `"treasury.near" != "applicant"`.
7. No account can ever call `claim_fee` successfully for this transfer. `remove_transfer_message` (L1094) is never called, `unlock_tokens_if_needed` (L2684) is never called, and the fee tokens remain locked in `pending_transfers` forever.

To reproduce: write an integration test using the existing `near-workspaces` harness, set up a trusted relayer, call `sign_transfer` with a non-relayer `fee_recipient`, mock a `FinTransfer` prover result, and verify that both `treasury.near` and `applicant` fail `claim_fee` while the `pending_transfers` entry persists.