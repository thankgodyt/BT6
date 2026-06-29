Audit Report

## Title
Trusted-Relayer Gate on `claim_fee` Permanently Freezes Earned Fee Tokens When Relayer Resigns or Is Revoked — (`near/omni-bridge/src/lib.rs`)

## Summary

`claim_fee` is decorated with `#[trusted_relayer]`, which rejects any caller not currently in the active-relayer set. `claim_fee_callback` independently requires the caller to equal the `fee_recipient` embedded in the on-chain proof. If a relayer resigns or is revoked after executing a fast transfer to a non-NEAR chain but before the destination-chain proof is submitted, neither the original relayer nor any substitute can satisfy both restrictions simultaneously, permanently freezing the fee tokens inside the bridge contract.

## Finding Description

Two independent restrictions in the fee-claim path create an irrecoverable dead-end:

**Restriction 1** — `claim_fee` at line 1055 carries `#[trusted_relayer]` (imported from `omni_utils::macros::trusted_relayer`, line 34). Any caller not currently in the active-relayer set is rejected before proof verification begins.

**Restriction 2** — `claim_fee_callback` at lines 1083–1086 requires `fee_recipient == *predecessor_account_id`. The `fee_recipient` is cryptographically bound in the destination-chain event proof; no other account can satisfy this check.

When a relayer executes a fast transfer to a non-NEAR chain, `fast_fin_transfer_to_other_chain` (lines 914–973) burns/locks the principal and stores a second-leg `TransferMessage` in `pending_transfers` with `origin_transfer_id = Some(fast_transfer.transfer_id.clone())` (line 956). The fee portion remains locked in the bridge's accounting until `claim_fee_callback` calls `send_fee_internal` (lines 2650–2701), which is the only code path that releases it.

If the relayer calls `resign_trusted_relayer` (confirmed in tests at `near/omni-tests/src/relayer_staking.rs` lines 336–368, where `is_trusted_relayer` returns `false` immediately after resignation) before the destination-chain proof is available:

- The original relayer fails Restriction 1 (`#[trusted_relayer]` panics).
- Any currently-trusted relayer fails Restriction 2 (`OnlyFeeRecipientCanClaim` panics).

No permissionless path exists to release the fee. The `pending_transfers` entry also persists indefinitely as a storage leak. The `#[trusted_relayer]` gate adds zero security benefit here because Restriction 2 already ensures only the correct party can collect the fee.

## Impact Explanation

Fee tokens earned by a relayer for executing a fast transfer to a non-NEAR destination chain are permanently frozen in the bridge contract. This constitutes **permanent freezing of bridged funds / fee mis-accounting** within the allowed NEAR Omni Bridge impact scope. The only escape is DAO intervention via `transfer_token_as_dao`, an out-of-band privileged action that does not restore the fee to the rightful relayer and is not a permissionless remedy.

## Likelihood Explanation

Low. The window requires a relayer to resign or be revoked after submitting a fast transfer but before the destination-chain proof is finalized and submitted. This window is narrow for fast-finalizing chains but realistic for Ethereum mainnet (multi-block finality) or in DAO-revocation scenarios where a relayer is removed for misconduct while holding pending fee claims. The DAO-revocation path is particularly concerning because it is externally triggered and the relayer has no control over its timing.

## Recommendation

Remove the `#[trusted_relayer]` attribute from `claim_fee`. The `fee_recipient == predecessor_account_id` check in `claim_fee_callback` already guarantees that only the correct party can collect the fee; the additional trusted-relayer gate provides no additional security and creates the described permanent-freeze condition. Alternatively, allow the `fee_recipient` to call `claim_fee` regardless of current relayer status, since the fee was earned at the time the fast transfer was executed.

## Proof of Concept

1. Relayer A becomes a trusted relayer (stake deposited, waiting period elapsed).
2. Relayer A calls `ft_transfer_call` with a `FastFinTransferMsg` targeting a Base-chain recipient. `fast_fin_transfer_to_other_chain` burns the principal, stores a second-leg `TransferMessage` in `pending_transfers` with `origin_transfer_id = Some(fast_transfer_id)`, and records `FastTransferStatus { relayer: RelayerA, finalised: false }`.
3. A regular relayer calls `sign_transfer` on the second-leg transfer. Because `fee > 0`, the `TransferMessage` remains in `pending_transfers` after signing.
4. Relayer A calls `resign_trusted_relayer`. Stake is returned; Relayer A is removed from the trusted set (`is_trusted_relayer` returns `false`).
5. The signed payload is submitted to Base. Base emits `FinTransfer` with `fee_recipient = RelayerA`.
6. Relayer A attempts `claim_fee` with the Base proof → panics at `#[trusted_relayer]` (line 1055) because Relayer A is no longer active.
7. Any other trusted relayer attempts `claim_fee` with the same proof → panics at `OnlyFeeRecipientCanClaim` (lines 1083–1086) because `fee_recipient (RelayerA) != predecessor_account_id`.
8. Fee tokens and the `pending_transfers` entry are permanently stuck. No permissionless recovery path exists.