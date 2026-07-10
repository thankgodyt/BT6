### Title
Missing Bounds Check on User-Supplied `vout` Before Slice Access in Refund Request - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `internal_request_refund` function accesses `transaction.output()[vout]` using a user-supplied `vout` index without first verifying that `vout` is within the bounds of the transaction's output vector. An unprivileged user can supply an out-of-bounds `vout`, causing the contract to panic and the caller to lose their attached storage deposit.

### Finding Description
In `internal_request_refund`, the decoded transaction's output vector is indexed directly with the caller-supplied `vout` parameter at line 167, before any bounds check is performed:

```rust
let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
```

The only input validation applied before this point is a size cap on `tx_bytes` (line 151) and a `refund_address` consistency check (lines 154–158). There is no check that `vout < transaction.output().len()`. If the caller supplies a `vout` that equals or exceeds the number of outputs in the decoded transaction, Rust's slice indexing panics unconditionally (overflow-checks are enabled in NEAR contracts), reverting the call and consuming the caller's attached deposit.

This is structurally identical to the reported `memcpy` bug: just as that function checks `offset > dest.len()` but misses the equal-to case and the combined `offset + source.len()` overflow, this code performs no length check at all before indexing into the output slice.

### Impact Explanation
The panic reverts the entire `internal_request_refund` call. The caller's attached NEAR deposit (required by `required_balance_for_request_refund`) is not refunded on a panic-revert in NEAR, so the caller loses that deposit. Bridge contract state is not corrupted, but the refund path is rendered unusable for any transaction where the caller provides an invalid `vout`. This matches the **Low** allowed impact: publicly reachable panic-driven fault in a production bridge path without direct theft.

### Likelihood Explanation
The `request_refund` entry point is publicly callable by any NEAR account that has made a BTC deposit. No privileged role is required. The only prerequisite is attaching the storage deposit and providing a valid `tx_bytes` payload. Supplying an out-of-bounds `vout` (e.g., `vout = 999` for a 1-output transaction) is trivially achievable by any user, whether by mistake or deliberately.

### Recommendation
Add an explicit bounds check immediately after decoding the transaction, before any output indexing:

```rust
let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
    .expect("Deserialization tx_bytes failed");

require!(
    vout < transaction.output().len(),
    format!("vout {} is out of bounds (tx has {} outputs)", vout, transaction.output().len())
);

let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
```

Apply the same guard in `request_refund_callback` at line 514 for defence-in-depth, since `vout` is re-used there after being stored in the `RefundRequest`.

### Proof of Concept

1. User sends a real BTC deposit transaction with 1 output (index 0) to the bridge deposit address.
2. User calls the public `request_refund` (or equivalent chain-specific entrypoint) with:
   - `tx_bytes`: the valid serialized deposit transaction
   - `vout`: `1` (or any value ≥ 1, which is out of bounds for a 1-output tx)
   - `refund_address`: any valid BTC address
   - Attached deposit: `required_balance_for_request_refund()`
3. Inside `internal_request_refund`, `crate::WrappedTransaction::decode` succeeds (the bytes are valid).
4. Execution reaches line 167: `transaction.output()[1]` — the vector has length 1, so Rust panics with an index-out-of-bounds error.
5. The NEAR runtime reverts the call. The attached deposit is consumed. The refund request is never stored. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L510-514)
```rust

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];
```
