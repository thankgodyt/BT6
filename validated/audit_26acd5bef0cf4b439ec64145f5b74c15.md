### Title
`execute_refund` Is Unnecessarily `#[payable]` — Attached NEAR Is Permanently Trapped - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`execute_refund` is declared `#[payable]` but never reads, validates, or refunds `env::attached_deposit()`. Any NEAR tokens a user attaches to the call are silently accepted and permanently locked in the contract with no recovery path.

### Finding Description
In NEAR, a function that is **not** annotated `#[payable]` will automatically panic if the caller attaches any deposit. Marking a function `#[payable]` opts out of that protection. The contract must then either consume the deposit intentionally (e.g. for storage) or call `assert_one_yocto()` to enforce exactly 1 yoctoNEAR.

`execute_refund` does neither:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs
#[payable]                          // ← accepts any deposit
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [1](#0-0) 

Neither `resolve_execute_refund_timelock` nor `internal_execute_refund` reads `env::attached_deposit()`. Contrast this with every other `#[payable]` function in the same contract that legitimately uses a deposit:

- `request_refund` → `internal_request_refund` enforces `env::attached_deposit() >= required_balance_for_request_refund()` [2](#0-1) 
- `cancel_withdraw` → calls `assert_one_yocto()` immediately [3](#0-2) 
- `active_utxo_management` → calls `assert_one_yocto()` immediately [4](#0-3) 

`execute_refund` has no such guard. The function is also unrestricted — no `#[trusted_relayer]` or `#[access_control_any]` — so any NEAR account can call it. [5](#0-4) 

### Impact Explanation
Any NEAR attached to an `execute_refund` call is permanently locked in the `satoshi-bridge` contract. The contract exposes no withdrawal or sweep function for accidentally deposited NEAR. The funds are irrecoverable without a contract upgrade. This matches the **Medium** allowed impact: *harmful smart-contract behavior without direct funds theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention.*

### Likelihood Explanation
`execute_refund` is a user-facing function that any NEAR account can call after the refund timelock expires. Users who are accustomed to NEAR functions requiring a small deposit (e.g. `request_refund` requires `required_balance_for_request_refund()`) may habitually attach NEAR to `execute_refund` as well. Wallet UIs and scripts that auto-attach a small deposit for storage safety would also trigger this silently. The function is on the critical user path of the refund lifecycle, making accidental attachment realistic.

### Recommendation
Remove the `#[payable]` attribute from `execute_refund`. The function requires no attached deposit; removing the attribute causes the NEAR runtime to automatically reject any call that attaches tokens, protecting users at zero cost.

```rust
// Before
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(...) -> PromiseOrValue<()> { ... }

// After
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(...) -> PromiseOrValue<()> { ... }
```

### Proof of Concept
1. Alice has a pending refund request for UTXO key `"abc123@0"` and the timelock has elapsed.
2. Alice calls `execute_refund("abc123@0", None)` and attaches 1 NEAR (e.g. expecting a storage fee similar to `request_refund`).
3. The NEAR runtime accepts the call because `#[payable]` is present.
4. `execute_refund` proceeds normally — `resolve_execute_refund_timelock` and `internal_execute_refund` never touch `env::attached_deposit()`.
5. The 1 NEAR is credited to the `satoshi-bridge` contract balance with no record of the sender and no mechanism to return it.
6. Alice's refund request is processed correctly, but her 1 NEAR is permanently lost. [1](#0-0)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-286)
```rust
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L371-372)
```rust
    pub fn active_utxo_management(&mut self, input: Vec<OutPoint>, output: Vec<TxOut>) {
        assert_one_yocto();
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

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```
