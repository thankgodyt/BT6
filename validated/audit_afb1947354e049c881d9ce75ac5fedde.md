### Title
Permissionless `execute_refund` Allows Third Party to Override User's Intended Refund Output Path via `chain_specific_data` - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`execute_refund` is a permissionless function that accepts a caller-supplied `chain_specific_data` parameter. On Zcash, this parameter determines whether the refund is executed as a shielded (Orchard) or transparent transaction. Because the user's intended output path is never persisted in the `RefundRequest`, any third party can call `execute_refund` after the timelock and force a different execution path than the one the user intended.

### Finding Description
When a user calls `request_refund`, the stored `RefundRequest` captures only a transparent `refund_address: String`. There is no field recording whether the user intended a shielded (Orchard) or transparent refund. [1](#0-0) 

After the timelock elapses, `execute_refund` is callable by anyone — it carries no `#[access_control_any]` guard, only a pause check: [2](#0-1) 

The caller freely supplies `chain_specific_data: Option<ChainSpecificData>`, which is passed verbatim into `internal_execute_refund`. The doc comment for this parameter states explicitly:

> "Zcash only: `Some` with an Orchard bundle for a shielded refund, `None` for transparent." [3](#0-2) 

Because the user's intended output path is not stored in `RefundRequest`, a third party can call `execute_refund` with `chain_specific_data = Some(orchard_bundle)` even when the user intended a transparent refund (or vice versa). The Orchard bundle supplied by the attacker contains the recipient address for the shielded output, which need not match the user's stored `refund_address`.

### Impact Explanation
On Zcash, if a third party calls `execute_refund` with a crafted Orchard bundle whose recipient is the attacker's own shielded address, the refund UTXO is spent sending ZEC to the attacker rather than the user. This constitutes unauthorized redirection of user funds — a Critical impact. At minimum, even if the Orchard bundle's recipient is validated against the stored address, forcing a shielded execution when the user intended transparent (or vice versa) can permanently lock the user out of their funds if the shielded path fails or produces an unspendable output, matching the Medium impact category of "stuck bridge state requiring operator intervention."

### Likelihood Explanation
`execute_refund` is explicitly designed to be permissionless — the protocol documentation and code comments confirm that "anyone can call `execute_refund`" after the timelock. An attacker only needs to monitor the chain for pending `RefundRequest` entries and front-run or race the legitimate finalization with a crafted `chain_specific_data` payload. No privileged access, leaked keys, or external dependency compromise is required.

### Recommendation
Persist the user's intended output path (shielded vs. transparent, and if shielded, the intended recipient) inside `RefundRequest` at `request_refund` time. During permissionless `execute_refund`, enforce that `chain_specific_data` matches the stored intent, or restrict permissionless callers to only the transparent path (using the stored `refund_address`) and require the user themselves to supply an Orchard bundle for shielded execution. [1](#0-0) 

### Proof of Concept
1. User calls `request_refund(deposit_msg, "t1UserTransparentAddress...", tx_bytes, vout, proof, None)` on the Zcash-compiled bridge. The `RefundRequest` is stored with `refund_address = "t1UserTransparentAddress..."` and no shielded-path intent.
2. Timelock elapses (or `unsafe_refund_timelock_sec` passes).
3. Attacker calls `execute_refund(utxo_storage_key, Some(attacker_orchard_bundle))` where `attacker_orchard_bundle` encodes the attacker's own Orchard recipient address.
4. `internal_execute_refund` receives the attacker-controlled `chain_specific_data` and constructs a shielded Zcash transaction paying the attacker's Orchard address.
5. The MPC signs and broadcasts the transaction. The user's deposit UTXO is spent to the attacker; the user receives nothing. [2](#0-1) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L32-47)
```rust
pub struct RefundRequest {
    pub deposit_msg_json: String,
    pub utxo_storage_key: String,
    pub tx_bytes: Base64VecU8,
    pub vout: usize,
    pub amount: u128,
    pub refund_address: String,
    pub gas_fee: u128,
    pub created_at_sec: u32,
    /// Set once `execute_refund` has built a refund transaction for this request.
    /// While `true` the request is kept (not removed) so `execute_refund` can be
    /// called again to re-create the transaction (e.g. after a consensus branch
    /// change); it is removed only when the refund is finalized in
    /// `verify_refund_finalize`.
    pub executed: bool,
}
```

**File:** contracts/satoshi-bridge/src/refund.rs (L315-325)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L576-589)
```rust
    ///
    /// * `utxo_storage_key` - Refund request key (`{tx_id}@{vout}`).
    /// * `chain_specific_data` - Zcash only: `Some` with an Orchard bundle for a
    ///   shielded refund, `None` for transparent. Ignored on Bitcoin.
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
