The critical detail is in the workspace `Cargo.toml`: [1](#0-0) 

`overflow-checks = true` is set in the release profile. This means the subtraction `len - skip_n` is **not** a silent wrapping operation — it is a checked subtraction that **panics (traps the WASM)** when `skip_n > len`, even in release builds.

The pattern is identical across all eight functions: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

None of these functions have any ACL guard — they are fully public view entrypoints. [9](#0-8) 

---

### Title
Unprivileged caller can panic all eight paged view functions via `from_index > len` with `limit=None` — (`contracts/satoshi-bridge/src/api/view.rs`)

### Summary
Every paged view function computes `take_n = limit.unwrap_or(len - skip_n)`. With `overflow-checks = true` in the release profile, supplying `from_index` greater than the collection length and omitting `limit` causes a checked-subtraction underflow that traps the WASM execution, panicking the call.

### Finding Description
The eight functions `get_accounts_paged`, `get_lost_found_paged`, `get_utxos_paged`, `get_unavailable_utxos_paged`, `get_btc_pending_infos_paged`, `get_rbf_txs_paged`, `get_post_action_msg_templates_paged`, and `get_refund_requests_paged` all share the same pattern:

```rust
let len   = usize::try_from(self.data().collection.len())...;
let skip_n = from_index.unwrap_or(0);
let take_n = limit.unwrap_or(len - skip_n);   // panics when skip_n > len
```

Because the workspace release profile sets `overflow-checks = true`, the subtraction `len - skip_n` is a **checked** operation. When `skip_n > len` (i.e., `from_index` exceeds the collection size), the subtraction underflows and the WASM contract traps. No guard prevents an arbitrary caller from supplying such a value.

### Impact Explanation
This is a publicly reachable panic-driven fault in production bridge view paths. View-function panics on NEAR do not modify contract state, so no funds are directly at risk. However:
- Any off-chain indexer, monitoring tool, or dApp that calls these functions with a stale/large `from_index` will receive a hard error instead of an empty page.
- The broken invariant ("paged view functions are safe for arbitrary caller-supplied indices") is violated for all eight entrypoints simultaneously.

Impact classification: **Low** — publicly reachable invariant-violation / panic-driven fault in production bridge paths without direct theft.

### Likelihood Explanation
Trivially reachable by any unprivileged account with a single RPC call. No tokens, storage deposit, or special role required. The trigger condition (`from_index = len + 1, limit = None`) is a natural edge case for any pagination client.

### Recommendation
Replace the bare subtraction with a saturating variant:

```rust
let take_n = limit.unwrap_or_else(|| len.saturating_sub(skip_n));
```

This returns `0` when `skip_n >= len`, causing the iterator to yield an empty result rather than panicking — the correct semantic for "page past the end."

### Proof of Concept
```rust
// Pseudocode — call against a deployed contract where utxos.len() == N
contract.get_utxos_paged(from_index: Some(N + 1), limit: None)
// With overflow-checks = true, len - skip_n = N - (N+1) traps the WASM.
// Same call works identically against all seven other paged functions.
```

### Citations

**File:** Cargo.toml (L21-27)
```text
[profile.release]
codegen-units = 1
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L123-139)
```rust
    pub fn get_lost_found_paged(
        &self,
        from_index: Option<usize>,
        limit: Option<usize>,
    ) -> HashMap<AccountId, U128> {
        let len = usize::try_from(self.data().lost_found.len())
            .unwrap_or_else(|_| env::panic_str("Too many lost_found accounts"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
        self.data()
            .lost_found
            .iter()
            .skip(skip_n)
            .take(take_n)
            .map(|(k, v)| (k.clone(), U128(*v)))
            .collect()
    }
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L158-161)
```rust
        let len = usize::try_from(self.data().utxos.len())
            .unwrap_or_else(|_| env::panic_str("Too many utxos"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L183-186)
```rust
        let len = usize::try_from(self.data().unavailable_utxos.len())
            .unwrap_or_else(|_| env::panic_str("Too many unavailable_utxos"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L216-219)
```rust
        let len = usize::try_from(self.data().btc_pending_infos.len())
            .unwrap_or_else(|_| env::panic_str("Too many btc_pending_infos"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L254-257)
```rust
        let len = usize::try_from(self.data().rbf_txs.len())
            .unwrap_or_else(|_| env::panic_str("Too many rbf_txs"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L287-290)
```rust
        let len = usize::try_from(self.data().post_action_msg_templates.len())
            .unwrap_or_else(|_| env::panic_str("Too many post_action_msg_templates"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L309-312)
```rust
        let len = usize::try_from(self.data().refund_requests.len())
            .unwrap_or_else(|_| env::panic_str("Too many refund_requests"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```
