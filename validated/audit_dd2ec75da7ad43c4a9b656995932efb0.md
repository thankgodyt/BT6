### Title
Excess NEAR Attached Deposit Not Returned in `execute_refund` — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`execute_refund` is a publicly callable `#[payable]` function that requires an attached NEAR deposit via a `>=` check. Any NEAR attached beyond the required minimum is silently absorbed by the contract and never returned to the caller.

### Finding Description
`execute_refund` (bridge.rs:580-589) is marked `#[payable]` and delegates its deposit validation to `resolve_execute_refund_timelock` (refund.rs:201-228). That helper enforces:

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
``` [1](#0-0) 

The `>=` operator accepts any deposit at or above the minimum. After the check, execution continues into `internal_execute_refund`, which builds a cross-contract promise chain to fetch the last block height and then calls `execute_refund_callback`. Neither the helper nor the callback issues a `Promise::new(env::predecessor_account_id()).transfer(excess)` to return the surplus. [2](#0-1) 

Contrast this with `request_refund`, whose API doc explicitly states *"The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee"* — an intentional design choice documented in the code. [3](#0-2) 

No equivalent disclaimer exists for `execute_refund`. The refund-flow documentation shows an ordinary user (`U`) calling `execute_refund` directly, confirming it is a public entry point. [4](#0-3) 

### Impact Explanation
Any caller of `execute_refund` who attaches more NEAR than `required_balance_for_execute_refund()` permanently loses the excess to the bridge contract. Because the function is publicly reachable and the required amount is a storage-deposit figure (not prominently surfaced in UX), accidental overpayment is realistic. The lost funds are NEAR tokens, not BTC/nBTC, so there is no unauthorized minting or BTC theft; the impact is a direct, permanent loss of the caller's NEAR.

This fits: **Low — Publicly reachable invariant-violation / stuck-state / panic-driven fault in production bridge/token paths without direct theft.**

### Likelihood Explanation
Any user who calls `execute_refund` and attaches slightly more NEAR than the exact minimum (e.g., rounding up, using a wallet default, or following an outdated guide) triggers the loss. The function is callable by anyone after the timelock, making the exposure broad.

### Recommendation
After the `>=` guard passes, compute the excess and return it:

```rust
let required = self.required_balance_for_execute_refund();
let attached = env::attached_deposit();
require!(attached >= required, "Insufficient deposit for storage");
let excess = attached.as_yoctonear() - required.as_yoctonear();
if excess > 0 {
    Promise::new(env::predecessor_account_id())
        .transfer(NearToken::from_yoctonear(excess));
}
```

Alternatively, replace `>=` with `==` (as the TokensFarm re-audit did) so callers must attach exactly the required amount, eliminating the ambiguity entirely.

### Proof of Concept
1. Query `required_balance_for_execute_refund()` — suppose it returns `X` yoctoNEAR.
2. Call `execute_refund(utxo_storage_key, None)` with `attached_deposit = X + 1_000_000_000_000_000_000_000_000` (1 NEAR extra).
3. The `require!(attached >= required)` check passes.
4. `internal_execute_refund` is called; no refund transfer is issued.
5. The 1 extra NEAR is permanently credited to the bridge contract's balance, not returned to the caller. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L28-47)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let caller = env::predecessor_account_id();
        PromiseOrValue::Promise(
            self.get_last_block_height_promise().then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_EXECUTE_REFUND_CALLBACK)
                    .execute_refund_callback(
                        utxo_storage_key,
                        caller,
                        timelock_sec,
                        chain_specific_data,
                    ),
            ),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L488-491)
```rust
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
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

**File:** doc/refund-flow.md (L70-72)
```markdown
    U->>B: execute_refund(utxo_storage_key)<br/>📄 api/bridge.rs:454
    Note over B: Check: timelock passed?<br/>Check: UTXO not in verified_deposit_utxo?
    Note over B: Build PSBT:<br/>input = deposit UTXO<br/>output = refund_address<br/>remainder = gas fee
```
