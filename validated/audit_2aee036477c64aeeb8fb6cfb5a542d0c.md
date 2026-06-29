Audit Report

## Title
`#[trusted_relayer]` on `claim_fee` permanently freezes earned fee tokens for resigned/revoked relayers — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`claim_fee` is gated by `#[trusted_relayer]` at L1055, which panics before any proof verification if the caller is not an active staker in the relayer registry. The callback `claim_fee_callback` already enforces `fee_recipient == predecessor_account_id` against a cryptographically verified proof, making the outer guard redundant. Any relayer who resigns or is DAO-revoked after calling `sign_transfer` (which embeds their address as `fee_recipient` in an MPC-signed payload) is permanently blocked from claiming legitimately earned fees, causing those tokens to be frozen inside the bridge contract.

## Finding Description
**Outer gate — `#[trusted_relayer]` on `claim_fee` (L1054–1064):**
```rust
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
```
The `#[trusted_relayer]` macro (configured at the impl block with `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)`) calls `is_trusted_relayer(predecessor)` and panics if the caller is not an active staker. A resigned or DAO-revoked relayer holds neither the `DAO` nor `UnrestrictedRelayer` bypass role, so this check unconditionally rejects them.

**Inner gate — `fee_recipient == predecessor_account_id` in `claim_fee_callback` (L1083–1086):**
```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```
The `fee_recipient` is extracted from the `ProverResult::FinTransfer` returned by the on-chain prover, which verifies the cryptographic proof of the foreign-chain `FinTransfer` event. That event's `fee_recipient` field is bound to the MPC-signed `TransferMessagePayload` produced at `sign_transfer` time (L491–500). Because the proof is verified on-chain and the `fee_recipient` is bound to the MPC signature, this inner check already provides complete, unforgeable authorization. The outer `#[trusted_relayer]` guard adds nothing to security.

**Exploit path:**
1. Trusted relayer R calls `sign_transfer(transfer_id=T, fee_recipient=Some(R), fee=F)`. The MPC signs a payload encoding `fee_recipient=R`.
2. The foreign chain finalizes the transfer; the `FinTransfer` event records `fee_recipient=R`.
3. R calls `resign_trusted_relayer()` (or DAO calls `reject_relayer_application(R)`). `is_trusted_relayer(R)` now returns `false`.
4. R calls `claim_fee(ClaimFeeArgs { chain_kind, prover_args: proof_of_step_2 })`. The `#[trusted_relayer]` macro fires before any proof verification and panics. The proof is never verified; `claim_fee_callback` is never reached.
5. Fee tokens `F` remain locked in the bridge's token balance. `pending_transfers[T]` is never removed.

For fast transfers to other chains, the relayer pre-pays the recipient from their own balance and expects to recover that amount plus fee via `claim_fee` after the origin-chain proof arrives. If `claim_fee` is blocked, the relayer's pre-paid tokens are also frozen (L914–972).

The only recovery path is a DAO call to `transfer_token_as_dao` (L1511–1530), which requires admin intervention, does not clean up `pending_transfers`, and is not guaranteed to be executed.

## Impact Explanation
Permanent freezing of bridged fee tokens inside the bridge contract. The fee amount `F` is held in the bridge's token balance and cannot be released by any permissionless means once the relayer loses trusted status. For fast transfers, the relayer's pre-paid principal is also frozen. This matches the allowed impact: **permanent freezing of bridged funds**.

## Likelihood Explanation
Relayer churn is a normal operational event: relayers resign voluntarily to recover their staked NEAR, or the DAO revokes them for policy reasons. The window between `sign_transfer` (which records `fee_recipient`) and `claim_fee` (which requires a foreign-chain finality proof) spans at minimum the finality time of the source chain — minutes to hours for EVM L2s via Wormhole, longer for Ethereum L1. Any relayer who resigns or is revoked during this window loses their fee claim. No exotic assumptions are required; the scenario is a straightforward consequence of normal protocol operations.

## Recommendation
Remove `#[trusted_relayer]` from `claim_fee`. The proof verification and the `fee_recipient == predecessor_account_id` check in `claim_fee_callback` already provide complete, cryptographically sound authorization. Any account that can produce a valid proof naming itself as `fee_recipient` is the legitimate claimant.

```rust
// Before
#[payable]
#[trusted_relayer]          // remove this
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { … }

// After
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { … }
```

## Proof of Concept
```
1. Deploy bridge contract; configure relayer registry with stake_required=1000 NEAR.
2. Account R applies and is promoted to trusted relayer (wait past waiting_period_ns).
3. A user initiates a transfer; R calls sign_transfer(transfer_id=T, fee_recipient=Some(R), fee=F).
   → MPC signs payload; fee_recipient=R is embedded in the MPC signature.
4. Foreign chain finalizes the transfer; emits FinTransfer(transfer_id=T, fee_recipient=R).
5. R calls resign_trusted_relayer().
   → is_trusted_relayer(R) returns false; R's stake is returned.
6. R calls claim_fee(ClaimFeeArgs { chain_kind, prover_args: valid_proof_of_step_4 }).
   → #[trusted_relayer] macro checks is_trusted_relayer(R) → false → PANIC.
   → Proof is never verified; claim_fee_callback is never reached.
7. Observe: fee tokens F remain in bridge token balance; pending_transfers[T] persists.
   R cannot recover F by any permissionless means.
```

This can be demonstrated as an integration test using the existing `near/omni-tests` framework: promote a relayer, call `sign_transfer`, fast-forward past finality, call `resign_trusted_relayer`, then assert that `claim_fee` with a valid mock proof panics with the trusted-relayer error rather than the fee-recipient error.