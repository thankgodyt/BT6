Audit Report

## Title
Relayer Funds Permanently Lost When `send_tokens` Fails in `utxo_fin_transfer_fast` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
In `utxo_fin_transfer_fast`, the fast-transfer record is permanently removed or marked finalised in the same transaction before `send_tokens(...).detach()` is scheduled. Because `.detach()` fires a NEAR receipt with no callback, any failure of that receipt leaves the relayer's pre-financed tokens locked inside the bridge contract with no recovery path. The developer has explicitly flagged this gap with a `// TODO: check how to deal with failed send_tokens` comment at the call site.

## Finding Description
`utxo_fin_transfer` detects an existing fast-transfer record and delegates to `utxo_fin_transfer_fast` (L2483–2485). Inside that function (L2529–2548), the state mutation is unconditional and occurs before the async token transfer:

- If the destination is NEAR: `remove_fast_transfer` permanently deletes the record (L2530).
- Otherwise: `mark_fast_transfer_as_finalised` permanently sets the `finalised` flag (L2533).

Immediately after, `send_tokens(...).detach()` (L2542–2548) schedules an `ft_transfer` or `mint` receipt with no `.then(callback)`. NEAR's execution model guarantees that the state mutations above are committed to storage when the current call returns, regardless of whether the detached receipt later succeeds or panics. If the receipt fails, the fast-transfer record is already gone or finalised, so the repayment cannot be retried.

An analogous pattern exists in `process_fin_transfer_to_other_chain` (L2028–2040): `send_tokens(...).detach()` is called and then `mark_fast_transfer_as_finalised` is called in the same synchronous frame, so both state changes are committed together before the receipt outcome is known.

Concrete failure modes for the detached receipt:
- The relayer unregisters their NEP-141 storage between the fast transfer and finalization, causing `ft_transfer` to panic.
- The token contract is upgraded or paused between the two events.
- For bridge-deployed tokens, `mint` panics due to a contract-level edge case.

None of these require attacker privilege; they arise from ordinary operational conditions.

## Impact Explanation
When a relayer executes a fast transfer, they deposit their own tokens into the bridge to pre-finance the user. The bridge owes the relayer a repayment upon UTXO finalization. If `send_tokens` fails after `.detach()`, the tokens remain locked inside the bridge contract while the fast-transfer record is already removed or finalised. There is no admin recovery function, no retry mechanism, and no on-chain signal of the failure. This constitutes permanent freezing of bridged funds, matching the Critical impact scope.

## Likelihood Explanation
A relayer is an external, unprivileged actor who interacts through public contract calls. The failure condition does not require attacker privilege: NEP-141 storage unregistration between fast-transfer and finalization is a realistic operational event, and token contract upgrades or panics are plausible over the lifetime of a bridge. The developer's own TODO comment confirms awareness of the unresolved gap.

## Recommendation
Replace `.detach()` in `utxo_fin_transfer_fast` with a chained callback (`.then(Self::ext(...).utxo_fin_transfer_fast_callback(...))`). On callback failure, restore the fast-transfer record (re-insert or clear the `finalised` flag) so the repayment can be retried. Apply the same fix to the analogous site in `process_fin_transfer_to_other_chain`. Alternatively, introduce a permissioned recovery function that allows the DAO or the relayer to reclaim tokens when the initial repayment receipt failed, guarded by proof that the receipt panicked.

## Proof of Concept
1. Relayer calls `ft_on_transfer` with a `FastFinTransfer` message, depositing their own tokens into the bridge to pre-finance the user. The fast-transfer record is stored with `finalised = false`.
2. The relayer subsequently unregisters their NEP-141 storage on the token contract (a valid, permissionless action).
3. The UTXO connector calls `ft_on_transfer` with a `UtxoFinTransfer` message to finalize the original transfer.
4. `utxo_fin_transfer` finds the fast-transfer record and calls `utxo_fin_transfer_fast`.
5. `utxo_fin_transfer_fast` calls `remove_fast_transfer` (destination = NEAR) or `mark_fast_transfer_as_finalised` (destination = other chain), permanently committing the state change.
6. `send_tokens(...).detach()` schedules an `ft_transfer` receipt to the relayer. Because the relayer has no storage registration, the `ft_transfer` panics and the receipt is silently dropped.
7. The fast-transfer record is already gone; no retry is possible. The relayer's pre-financed tokens remain locked in the bridge contract permanently.