### Title
Immutable `bridge_id` in nBTC Token Contract Prevents Bridge Migration or Privilege Revocation — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `bridge_id` field in the nBTC token contract is set once at initialization and can never be changed. Unlike the `controller` field (which has a `set_controller()` function), there is no `set_bridge_id()` equivalent. If the bridge contract must be migrated to a new NEAR account ID, or if the bridge account is compromised and its minting/burning privileges must be revoked, the nBTC contract provides no mechanism to do so, leaving the bridge permanently stuck.

### Finding Description
In `contracts/nbtc/src/lib.rs`, the `Contract` struct stores two privileged account IDs:

```rust
pub struct Contract {
    controller: AccountId,   // changeable via set_controller()
    bridge_id: AccountId,    // NO setter — immutable after new()
    ...
}
```

The `bridge_id` is the **sole account** authorized to call `mint`, `safe_mint`, and `burn`:

```rust
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
```

The `controller` role has a dedicated setter (`set_controller`), but `bridge_id` has no equivalent. Once set in `new()`, it is permanently fixed. The only workaround is a full contract upgrade via `upgrade_and_migrate()`, which is a heavyweight operation and not a clean operational mechanism.

### Impact Explanation
If the `satoshi-bridge` contract must be redeployed to a **new NEAR account ID** (e.g., due to a security incident, account compromise, or architectural migration), the nBTC contract would still only accept `mint`/`burn` calls from the old bridge address. The new bridge would be unable to mint nBTC for deposits or burn nBTC for withdrawals. All bridged funds would be permanently locked in a stuck state — users could not withdraw their BTC — until the nBTC contract itself is upgraded. This maps to: **Medium — stuck bridge state requiring operator intervention**.

### Likelihood Explanation
The satoshi-bridge contract uses the `Upgradable` plugin (in-place code upgrade, same account ID), which mitigates the risk for routine upgrades. However, if the bridge account itself is compromised or a full account migration is required, the inability to update `bridge_id` becomes a critical operational gap. Likelihood is low under normal operations but non-negligible in incident-response scenarios.

### Recommendation
Add a `set_bridge_id()` function to the nBTC contract, gated behind `assert_controller()` (and optionally `assert_one_yocto()`), mirroring the existing `set_controller()` pattern:

```rust
#[payable]
pub fn set_bridge_id(&mut self, bridge_id: AccountId) {
    assert_one_yocto();
    self.assert_controller();
    self.bridge_id = bridge_id;
}
```

### Proof of Concept

1. Deploy `nbtc` contract with `bridge_id = satoshi-bridge.near`.
2. Suppose `satoshi-bridge.near` is compromised; the DAO deploys a new bridge at `satoshi-bridge-v2.near`.
3. `satoshi-bridge-v2.near` calls `mint(...)` → panics with `"Not Allow"` because `bridge_id` still points to `satoshi-bridge.near`.
4. No `set_bridge_id()` exists; the only recourse is a full nBTC contract upgrade via `upgrade_and_migrate()`.
5. Until the upgrade is executed, all deposit minting and withdrawal burning are permanently blocked.

**Root cause:** [1](#0-0)  — `bridge_id` stored in state with no setter.

**`assert_bridge` gate on mint/burn:** [2](#0-1) 

**`set_controller` exists (contrast — no equivalent for `bridge_id`):** [3](#0-2) 

**`mint` and `burn` gated exclusively by `assert_bridge`:** [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/nbtc/src/lib.rs (L24-29)
```rust
pub struct Contract {
    controller: AccountId,
    bridge_id: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
```

**File:** contracts/nbtc/src/lib.rs (L93-98)
```rust
    #[payable]
    pub fn set_controller(&mut self, controller: AccountId) {
        assert_one_yocto();
        self.assert_controller();
        self.controller = controller;
    }
```

**File:** contracts/nbtc/src/lib.rs (L126-135)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L150-158)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
```

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```
