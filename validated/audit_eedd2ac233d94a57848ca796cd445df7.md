Audit Report

## Title
Trusted-Relayer Guard on `claim_fee()` Permanently Locks Earned Fee Tokens After Relayer Removal - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`claim_fee()` is gated by `#[trusted_relayer]`, which rejects any caller who is not currently a trusted relayer. If a relayer is removed from the trusted set (via voluntary `resign_trusted_relayer` or DAO-forced `reject_relayer_application`) after calling `sign_transfer()` but before calling `claim_fee()`, the fee tokens they earned are permanently locked in the bridge contract. No substitute caller can recover them because `claim_fee_callback()` independently enforces `fee_recipient == predecessor_account_id`, and the `fee_recipient` is irrevocably fixed in the destination-chain proof.

## Finding Description
Two independent guards combine to create the lock:

**Guard 1:** `claim_fee()` carries a method-level `#[trusted_relayer]` attribute that rejects any caller not currently in the trusted-relayer set. The impl block configures `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)`, meaning DAO and `UnrestrictedRelayer` accounts can bypass this check.

**Guard 2:** `claim_fee_callback()` enforces `require!(fee_recipient == *predecessor_account_id, ...)`. The `fee_recipient` value comes from `fin_transfer.fee_recipient`, which is parsed from the destination-chain proof (the on-chain `FinTransfer` event). This value was fixed at `sign_transfer()` time when the relayer's account ID was embedded in the `TransferMessagePayload` and MPC-signed, then emitted by the destination chain contract.

The bypass roles do not help: if the DAO calls `claim_fee`, it passes Guard 1, but `claim_fee_callback` receives `predecessor_account_id = DAO_account` while `fee_recipient = removed_relayer_account`, causing the `require!` to panic. The same applies to any `UnrestrictedRelayer` substitute caller.

The only on-chain recovery path would require the DAO to re-grant the removed relayer the `UnrestrictedRelayer` role or re-admit them as a trusted relayer — there is no permissionless recovery function.

## Impact Explanation
The fee tokens are NEP-141 tokens originally deposited by users via `ft_transfer_call` and held in `pending_transfers`. When `claim_fee_callback` never succeeds, `remove_transfer_message` is never called, and the fee portion of the transfer remains locked in `pending_transfers` indefinitely with no on-chain permissionless recovery path. This constitutes permanent freezing of bridged user funds, matching the Critical impact class.

## Likelihood Explanation
The scenario is realistic and can arise through normal protocol operation:
- Relayers routinely sign many transfers before claiming fees, creating a window between `sign_transfer` and `claim_fee` that can span multiple blocks or days (destination-chain finalization proof must be obtained first).
- A relayer can voluntarily call `resign_trusted_relayer` to recover their stake without first draining all pending fee claims.
- The DAO can forcibly revoke a relayer at any time via `reject_relayer_application` for misconduct or operational reasons.
- Neither the relayer nor the DAO has any on-chain signal that pending unclaimed fees exist before removal.

## Recommendation
Remove the `#[trusted_relayer]` attribute from `claim_fee()`. The function is already protected by:
1. Cryptographic proof verification via `verify_proof` (ensures the destination-chain event is authentic).
2. The `fee_recipient == predecessor_account_id` check in `claim_fee_callback()`, which ensures only the legitimate fee earner can collect.
3. The `factories` emitter check in `claim_fee_callback()`, which ensures the proof comes from a registered factory.

The `#[trusted_relayer]` guard adds no security value on `claim_fee` and only risks permanently locking legitimately earned fees.

## Proof of Concept
1. Relayer R becomes trusted (stake deposited, waiting period elapsed).
2. R calls `sign_transfer(transfer_id, fee_recipient = Some(R), fee)` — MPC signs a payload embedding R as `fee_recipient`; the destination chain finalizes the transfer and emits `FinTransfer(... feeRecipient = R)`.
3. DAO calls `reject_relayer_application(R)` — R is removed from the trusted set and R's stake is transferred to the DAO.
4. R calls `claim_fee(proof_args)` — the `#[trusted_relayer]` check at line 1055 fires and the call is rejected.
5. DAO calls `claim_fee(proof_args)` — passes Guard 1 (DAO is a bypass role), but `claim_fee_callback` receives `predecessor_account_id = DAO` while `fin_transfer.fee_recipient = R`, causing `require!(fee_recipient == *predecessor_account_id)` to panic.
6. The fee tokens remain locked in `pending_transfers` with no permissionless recovery path.

Reproducible as a sandbox integration test: deploy the bridge, set up a trusted relayer, call `sign_transfer` with a mock MPC signer, fast-forward, call `reject_relayer_application`, then attempt `claim_fee` from both the removed relayer and the DAO account — both calls fail, and the transfer entry persists in `pending_transfers`.