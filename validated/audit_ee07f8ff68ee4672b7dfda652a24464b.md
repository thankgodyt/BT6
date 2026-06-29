Audit Report

## Title
Relayer Funds Permanently Frozen When Detached `send_tokens` Receipt Fails in `utxo_fin_transfer_fast` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
In `utxo_fin_transfer_fast`, the fast-transfer record is permanently removed or marked finalised in the same transaction that schedules the relayer repayment via `send_tokens(...).detach()`. Because `.detach()` fires the token transfer as a separate NEAR receipt with no callback, any failure of that receipt leaves the state mutation committed and the relayer's pre-financed tokens locked inside the bridge contract with no retry or recovery path. The developer has explicitly acknowledged this gap with a `// TODO: check how to deal with failed send_tokens` comment at the call site.

## Finding Description
When a UTXO-chain finalization arrives for a transfer that a relayer already fast-transferred, `utxo_fin_transfer` detects the existing fast-transfer record and delegates to `utxo_fin_transfer_fast`:

```rust
// near/omni-bridge/src/lib.rs L2483-2486
if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
    // TODO: check how to deal with failed send_tokens
    return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
}
```

Inside `utxo_fin_transfer_fast` (L2529-2548), the fast-transfer record is permanently mutated **before** the token transfer is attempted:

```rust
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // state permanently deleted
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // state permanently finalised
    U128(fast_transfer.amount_without_fee().near_expect(BridgeError::InvalidFee))
};

self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach();   // fire-and-forget, no failure callback
```

On NEAR, `.detach()` schedules the token transfer as a separate receipt. The state mutations (`remove_fast_transfer` / `mark_fast_transfer_as_finalised`) are committed atomically with the current receipt. If the subsequent `ft_transfer` or `mint` receipt fails for any reason, the state is already committed and cannot be rolled back. The fast-transfer record is gone or permanently finalised, so the repayment cannot be retried.

An identical pattern exists in `process_fin_transfer_to_other_chain` (L2028-2040): `send_tokens(...).detach()` is called and then `mark_fast_transfer_as_finalised` is called in the same transaction, so a failure of the detached receipt leaves the record permanently finalised with no recovery.

Realistic failure modes for the detached receipt include:
- The relayer's account lacks a storage registration for the specific NEP-141 token (`ft_transfer` panics with `"The account X is not registered"`).
- The token contract panics on `mint` or `ft_transfer` due to an edge case or upgrade.
- Gas exhaustion inside the token contract when the bridge is called with near-minimum gas.

None of these require attacker privilege; they arise from ordinary operational conditions.

## Impact Explanation
When a relayer performs a fast transfer, they send their own tokens to the bridge to pre-finance the user. The bridge owes the relayer a repayment when the original UTXO transfer is finalized. If the detached `send_tokens` receipt fails, the tokens remain locked inside the bridge contract while the fast-transfer record is already removed or finalised. There is no admin recovery function, no retry mechanism, and no event that signals the failure. The relayer's bridged funds are permanently frozen — a direct, concrete instance of permanent freezing of bridged funds, matching the Critical impact scope.

## Likelihood Explanation
Medium. The most realistic trigger is a missing NEP-141 storage registration on the relayer's account for the specific token being repaid. NEP-141 mandates `storage_deposit` before an account can receive tokens via `ft_transfer`; if the relayer registered storage for one token but not another, or if their registration was cleared, the repayment receipt will panic silently. This requires no attacker and no special privilege — it is an ordinary operational condition. The developer's own `// TODO` comment confirms awareness of the unresolved failure path.

## Recommendation
Replace the `.detach()` call in `utxo_fin_transfer_fast` with a proper callback chain. The state mutation (`remove_fast_transfer` / `mark_fast_transfer_as_finalised`) should be moved into the success branch of the callback; on failure, the callback should restore the fast-transfer record (re-insert or un-finalise it) so the repayment can be retried. Apply the same fix to the analogous site in `process_fin_transfer_to_other_chain`. Alternatively, introduce a permissioned recovery function that allows the DAO or the relayer to reclaim tokens when the initial repayment receipt failed, conditioned on verifying that the fast-transfer record was finalised but the repayment was never delivered.

## Proof of Concept
1. A trusted relayer calls `ft_transfer_call` with a `FastFinTransfer` message for a UTXO-chain transfer (e.g., Bitcoin → NEAR), sending their own tokens to the bridge to pre-finance the recipient. The fast-transfer record is stored via `add_fast_transfer`.
2. The UTXO connector later calls `ft_on_transfer` with a `UtxoFinTransfer` message to finalize the original transfer.
3. `utxo_fin_transfer` detects the existing fast-transfer record and calls `utxo_fin_transfer_fast`.
4. `utxo_fin_transfer_fast` calls `remove_fast_transfer` (destination = NEAR) or `mark_fast_transfer_as_finalised` (destination = other chain), permanently committing the state change in the current receipt.
5. `send_tokens(...).detach()` schedules the repayment as a separate receipt. The relayer's account has no storage registration for the token, so the `ft_transfer` receipt panics and is silently dropped.
6. The fast-transfer record is already gone; no retry is possible. The relayer's pre-financed tokens remain locked in the bridge contract with no recovery path.
7. To reproduce locally: deploy the bridge and a NEP-141 token contract on a NEAR sandbox; register the relayer for storage on the bridge but **not** on the token contract; execute steps 1–5 above; observe that the relayer's token balance is unchanged and the fast-transfer record no longer exists.