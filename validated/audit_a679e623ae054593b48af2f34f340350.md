### Title
Stale Trusted Relayer Status After `stake_required` Increase via `set_relayer_config` — (File: `near/omni-bridge/src/lib.rs`)

### Summary
When the DAO raises `stake_required` via `set_relayer_config`, existing active trusted relayers whose staked NEAR falls below the new threshold are never automatically re-evaluated. They retain their trusted relayer status indefinitely, allowing them to continue calling `fin_transfer`, `sign_transfer`, and `fast_fin_transfer` without meeting the updated security requirement.

### Finding Description
The bridge contract applies a `#[trusted_relayer]` macro that injects relayer management logic, including `apply_for_trusted_relayer`, `set_relayer_config`, and `is_trusted_relayer`. [1](#0-0) 

`set_relayer_config` updates the global `stake_required` and `waiting_period_ns` fields atomically. [2](#0-1) 

However, the stake check is only enforced at application time (`apply_for_trusted_relayer`). Once a relayer is promoted to active status, `is_trusted_relayer` returns `true` based on their stored `RelayerState`, not by re-comparing their staked amount against the current `stake_required`. [3](#0-2) 

There is no automatic sweep or invalidation of existing relayers when `stake_required` is raised. The DAO's only recourse is to manually call `reject_relayer_application` for each non-compliant relayer individually.

### Impact Explanation
Every privileged bridge operation is gated on `is_trusted_relayer`:

- `fin_transfer` — finalizes inbound cross-chain transfers and triggers token minting/release. [4](#0-3) 
- `sign_transfer` — requests an MPC signature to authorize outbound asset release on destination chains. [5](#0-4) 
- `fast_fin_transfer` — fronts user liquidity immediately, bypassing standard finality delays. [6](#0-5) 

A relayer who staked 1 000 NEAR when `stake_required` was 1 000 NEAR continues to hold these privileges after the DAO raises the threshold to, say, 5 000 NEAR. The updated stake requirement — intended to ensure relayers have sufficient economic skin-in-the-game — is silently bypassed for all pre-existing relayers. This is a role bypass: the relayer executes relayer-equivalent bridge actions without satisfying the current authorization threshold.

### Likelihood Explanation
The DAO can legitimately raise `stake_required` at any time (e.g., in response to NEAR price changes or a security incident). Any relayer who applied before the increase automatically becomes non-compliant but remains active. The DAO must enumerate and manually revoke every such relayer; missing even one leaves the weakened relayer operational. The entry path requires no special attacker capability beyond having previously applied as a relayer under the old threshold.

### Recommendation
In `set_relayer_config` (or in `is_trusted_relayer`), compare the relayer's stored stake against the current `stake_required` at the time of the trust check. If the stored stake is below the new threshold, treat the relayer as inactive. Alternatively, emit an on-chain event listing all relayers whose stake no longer meets the new requirement so the DAO can act promptly, or store the `stake_required` value at the time of activation inside `RelayerState` and re-validate it on each `is_trusted_relayer` call.

### Proof of Concept
1. DAO calls `set_relayer_config { stake_required: 1_000 NEAR, waiting_period_ns: 1s }`. [7](#0-6) 
2. Relayer calls `apply_for_trusted_relayer` with exactly 1 000 NEAR deposit; application is accepted. [8](#0-7) 
3. After the waiting period, `is_trusted_relayer` returns `true`; relayer is active. [9](#0-8) 
4. DAO calls `set_relayer_config { stake_required: 5_000 NEAR, ... }` to raise the bar. [10](#0-9) 
5. Relayer's stored stake is still 1 000 NEAR. `is_trusted_relayer` is never re-evaluated against the new threshold.
6. Relayer successfully calls `fin_transfer` and `sign_transfer`, executing relayer-equivalent bridge actions while holding only 20 % of the now-required stake — a direct role bypass of the updated authorization requirement. [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L445-447)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L671-673)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L755-756)
```rust
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");
```

**File:** near/omni-tests/src/relayer_staking.rs (L89-98)
```rust
        env.bridge_contract
            .call("set_relayer_config")
            .args_json(json!({
                "stake_required": U128(1_000 * 10u128.pow(24)),
                "waiting_period_ns": U64(1_000_000_000),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```

**File:** near/omni-tests/src/relayer_staking.rs (L103-109)
```rust
        let result = applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?;
        result.into_result()?;
```

**File:** near/omni-tests/src/relayer_staking.rs (L132-139)
```rust
        // After waiting period, relayer should be trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(is_trusted);
```

**File:** near/omni-tests/src/relayer_staking.rs (L511-531)
```rust
        // DAO updates config
        env.bridge_contract
            .call("set_relayer_config")
            .args_json(json!({
                "stake_required": U128(500 * 10u128.pow(24)),
                "waiting_period_ns": U64(86_400_000_000_000),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Verify updated
        let config: serde_json::Value = env
            .bridge_contract
            .view("get_relayer_config")
            .await?
            .json()?;
        let updated_stake = (500u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(updated_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(86_400_000_000_000)));
```

**File:** near/omni-bridge/src/migrate.rs (L42-43)
```rust
    pub relayers: LookupMap<AccountId, RelayerState>,
    pub relayer_config: RelayerConfig,
```
