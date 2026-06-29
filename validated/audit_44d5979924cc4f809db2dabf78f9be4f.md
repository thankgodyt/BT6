All cited code is confirmed in the repository. The vulnerability is real and well-evidenced.

Audit Report

## Title
Detached `send_tokens` Promise After `mark_fast_transfer_as_finalised` Causes Permanent Relayer Fund Loss — (File: near/omni-bridge/src/lib.rs)

## Summary
In `utxo_fin_transfer_fast`, for non-NEAR destination transfers, `mark_fast_transfer_as_finalised` commits `finalised=true` to persistent state and then `send_tokens(...).detach()` fires the reimbursement promise without any failure callback. If the promise fails, the state mutation is not rolled back, the fast transfer entry is permanently locked as finalised, and the relayer irrecoverably loses the tokens they advanced. The same structural flaw exists in `process_fin_transfer_to_other_chain`.

## Finding Description
In `utxo_fin_transfer_fast` (lines 2529–2548), for non-NEAR destinations:

```rust
self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // state committed
...
self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach(); // result never checked
```

`mark_fast_transfer_as_finalised` (lines 2270–2277) writes `finalised=true` into the `fast_transfers` map within the current execution frame. In NEAR, state mutations in the current frame are committed atomically when the transaction completes; a `.detach()`-ed promise runs in a separate receipt, and its failure does not roll back the parent transaction's state. The guard at lines 2524–2527 (`require!(!fast_transfer_status.finalised, ...)`) then permanently blocks any retry attempt. A developer-acknowledged TODO at line 2484 (`// TODO: check how to deal with failed send_tokens`) confirms the failure case is unhandled.

The same pattern appears in `process_fin_transfer_to_other_chain` (lines 2028–2040): `send_tokens(...).detach()` is called, then `mark_fast_transfer_as_finalised` is called in the same transaction frame — both committed regardless of the promise outcome.

The relayer's tokens are burned/locked at fast-transfer time in `fast_fin_transfer_to_other_chain` (lines 932–938). When `utxo_fin_transfer_fast` runs and `send_tokens` fails silently, those tokens are irrecoverable.

By contrast, the NEAR-destination path (lines 994–1011) correctly chains a `resolve_utxo_fin_transfer` callback via `.then(...)` to handle failure, demonstrating the developers know the correct pattern.

## Impact Explanation
A relayer who correctly executes a fast transfer for a BTC→EVM (or any non-NEAR destination) transfer permanently loses the tokens they advanced if the reimbursement `send_tokens` call fails. The fast transfer is marked finalised, the UTXO transfer is processed, and no admin or user function exists to reset the state or retry the send. This constitutes permanent loss of relayer funds — matching the Critical impact class of "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."

## Likelihood Explanation
The failure condition is realistic: a relayer that has not registered a storage deposit on the token contract (required by NEP-141 before `ft_transfer` can succeed), or a token contract that is paused or upgraded between fast-transfer and finalization, will cause `send_tokens` to fail. This is not a hypothetical edge case — it is a standard operational condition for any new relayer or newly supported token. The TODO comment at line 2484 confirms the developers are aware the failure case is unhandled.

## Recommendation
Replace `.detach()` with a chained callback that checks the promise result and, on failure, resets `finalised` back to `false` (or removes the entry) so the send can be retried. The correct pattern is already implemented for the NEAR-destination path: `send_tokens(...).then(Self::ext(...).resolve_utxo_fin_transfer(...))`. Apply the same pattern in both `utxo_fin_transfer_fast` and `process_fin_transfer_to_other_chain`, introducing a new `resolve_fast_transfer_send` callback that reverts `finalised` on failure.

## Proof of Concept
1. Deploy a mock NEP-141 token contract that panics on `ft_transfer`.
2. Register the token in the bridge; configure a UTXO chain connector.
3. Relayer calls `fast_fin_transfer` for a BTC→EVM transfer — tokens are burned/locked (`fast_fin_transfer_to_other_chain`, lines 932–938), fast transfer entry recorded with `finalised=false`.
4. UTXO connector calls `ft_on_transfer` with `UtxoFinTransfer` message → `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
5. `mark_fast_transfer_as_finalised` sets `finalised=true` (committed to state, lines 2270–2277).
6. `send_tokens(...).detach()` fires (line 2548); the mock token panics; the receipt fails silently.
7. Assert: `fast_transfer_status.finalised == true`, relayer token balance unchanged, any retry call panics with `FastTransferAlreadyFinalised` (lines 2524–2527), confirming no recovery path.