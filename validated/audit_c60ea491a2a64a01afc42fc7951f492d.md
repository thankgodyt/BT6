The decisive factor is the workspace `Cargo.toml`:

```toml
[profile.release]
overflow-checks = true
``` [1](#0-0) 

`overflow-checks = true` re-enables Rust's integer overflow/underflow panics even in the release (production) build. The subtraction `len - skip_n` at line 113 has no prior bounds check, so when `from_index > len` and `limit = None`, it panics in production. [2](#0-1) 

The same unguarded pattern is repeated in `get_lost_found_paged`, `get_post_action_msg_templates_paged`, and `get_refund_requests_paged`. [3](#0-2) [4](#0-3) [5](#0-4) 

---

### Title
Usize Underflow Panic in `get_accounts_paged` (and sibling paged view functions) via Attacker-Supplied `from_index` — (`contracts/satoshi-bridge/src/api/view.rs`)

### Summary
Any unprivileged caller can panic the NEAR contract's view layer by calling `get_accounts_paged` (or any of the three sibling paged-view functions) with `from_index` greater than the current collection length and `limit = None`. Because the workspace release profile sets `overflow-checks = true`, the usize subtraction `len - skip_n` aborts the WASM execution even in production builds.

### Finding Description
`get_accounts_paged` computes `take_n` as:

```rust
let skip_n = from_index.unwrap_or(0);
let take_n = limit.unwrap_or(len - skip_n);   // panics when skip_n > len
```

There is no guard of the form `if skip_n >= len { return HashMap::new(); }` before the subtraction. The workspace `Cargo.toml` explicitly sets `overflow-checks = true` under `[profile.release]`, so the subtraction traps (panics) in the production WASM binary whenever `skip_n > len`. The same pattern is present in `get_lost_found_paged`, `get_post_action_msg_templates_paged`, and `get_refund_requests_paged`.

### Impact Explanation
A panicking view call causes the NEAR RPC node to return an execution error for that call. Relayer and monitoring processes that poll these view functions to track bridge state will receive errors and may stall or misreport bridge health. This matches the **Low** allowed impact: "Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."

No funds are at risk directly; the impact is operational disruption of bridge monitoring and relayer tooling.

### Likelihood Explanation
The entrypoint is a public, permissionless view function — no deposit, no role, no authentication required. A single RPC call with `from_index = accounts.len() + 1` and `limit = null` is sufficient to reproduce the panic. Likelihood is **High** for triggering the fault; impact severity is **Low**.

### Recommendation
Add a saturation/bounds check before the subtraction:

```rust
let skip_n = from_index.unwrap_or(0).min(len);
let take_n = limit.unwrap_or(len - skip_n);
```

Or use saturating arithmetic:

```rust
let take_n = limit.unwrap_or_else(|| len.saturating_sub(skip_n));
```

Apply the same fix to `get_lost_found_paged`, `get_post_action_msg_templates_paged`, and `get_refund_requests_paged`.

### Proof of Concept
```rust
// Pseudocode — call via near-workspaces or NEAR CLI
contract.call("get_accounts_paged")
    .args_json(json!({ "from_index": usize::MAX }))  // limit omitted → None
    .view()
    .await;
// Expected (buggy): ExecutionError: "attempt to subtract with overflow"
// Expected (fixed):  returns empty HashMap {}
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

**File:** contracts/satoshi-bridge/src/api/view.rs (L110-113)
```rust
        let len = usize::try_from(self.data().accounts.len())
            .unwrap_or_else(|_| env::panic_str("Too many accounts"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L128-131)
```rust
        let len = usize::try_from(self.data().lost_found.len())
            .unwrap_or_else(|_| env::panic_str("Too many lost_found accounts"));
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
