### Title
Unchecked Caller-Supplied `vout` Causes Publicly Reachable Out-of-Bounds Panic in `request_refund` — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary
Any unprivileged NEAR account can call `request_refund` with a `vout` value that exceeds the number of outputs in the supplied `tx_bytes`, triggering an index-out-of-bounds panic in the production bridge path before any cross-contract verification occurs.

---

### Finding Description
In `internal_request_refund`, the caller-supplied `vout` parameter is used to directly index into `transaction.output()` with no prior bounds check:

```rust
// contracts/satoshi-bridge/src/refund.rs, line 167
let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
```

The public entry point `request_refund` (bridge.rs lines 510–534) carries no `#[trusted_relayer]` guard and no role restriction — only a minimum attached-deposit check and a `tx_bytes` size cap are enforced before reaching this line. Both checks pass even when `vout` is out of range.

The execution path is:

1. `request_refund` (bridge.rs:510) — public, `#[payable]`, no role gate
2. → `internal_request_refund` (refund.rs:137)
3. → `WrappedTransaction::decode` succeeds for any well-formed transaction
4. → `transaction.output()[vout]` **panics** if `vout >= transaction.output().len()`

The same unchecked pattern appears again in `request_refund_callback` at line 514 (`&transaction.output()[vout]`), though that callback is `#[private]` and not directly reachable by an attacker.

---

### Impact Explanation
**Low.** The panic causes the NEAR transaction to fail and revert; no contract state is mutated and the attached deposit is returned to the caller. There is no fund theft, no stuck state, and no persistent corruption. However, this is a publicly reachable panic-driven fault in a production bridge function (`request_refund`) that is part of the core refund lifecycle. The analog vulnerability class — out-of-bounds array access on caller-controlled index — matches the external report's MNT-03 finding.

---

### Likelihood Explanation
**High.** The trigger requires no special role, no leaked key, and no complex setup. An attacker constructs any syntactically valid BTC transaction with *N* outputs and calls `request_refund` with `vout = N` (or any value ≥ N). The only cost is the required attached storage deposit, which is returned on revert.

---

### Recommendation
Add an explicit bounds check immediately after decoding the transaction, before any output indexing:

```rust
require!(
    vout < transaction.output().len(),
    "vout out of bounds"
);
```

This mirrors the pattern already used elsewhere in the codebase for `vout` overflow (`u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow"))`), but that guard only catches integer-width overflow, not array-bounds violations.

---

### Proof of Concept

1. Construct a minimal valid BTC transaction with exactly **1 output** (index 0).
2. Call `request_refund` on the bridge contract with:
   - `tx_bytes` = the serialized transaction above
   - `vout = 1` (out of range)
   - `proof` = any syntactically valid `TxInclusionProof`
   - attached deposit ≥ `required_balance_for_request_refund()`
3. The contract decodes the transaction successfully, passes the size and deposit checks, then executes `transaction.output()[1]` on a single-output transaction.
4. Rust panics with an index-out-of-bounds error; the transaction reverts.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-153)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L161-168)
```rust
        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-534)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
```
