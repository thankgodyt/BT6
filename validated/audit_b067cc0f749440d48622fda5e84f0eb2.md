### Title
Immediate Pause by `PauseManager` Blocks Users from Recovering Funds via `claim_lost_found` and `execute_refund` - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `satoshi-bridge` contract uses `near_plugins::Pausable` with an immediately-effective pause mechanism. Both `claim_lost_found` (the only way to recover nBTC stranded in the bridge's lost-and-found ledger) and `execute_refund` (the only way to recover BTC from a failed/unfinalized deposit) are gated by `#[pause(except(roles(Role::DAO)))]`. When the `PauseManager` role pauses the contract — a legitimate emergency action — users with funds already committed to either of these recovery paths are silently locked out with no recourse until an `UnpauseManager` acts.

---

### Finding Description

The contract is declared with an immediate-effect pausable plugin:

```rust
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
``` [1](#0-0) 

The `PauseManager` role can pause the contract at any time with no timelock or delay. Two critical user-facing fund-recovery functions carry the `#[pause(except(roles(Role::DAO)))]` guard:

**1. `claim_lost_found`** — the sole mechanism for a user to retrieve nBTC that was routed to the bridge's `lost_found` ledger (e.g., when a `cancel_withdraw` RBF refund transfer failed):

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data_mut()
        .lost_found
        .remove(&account_id)
        .expect("The account does not have lostfound");
    self.internal_transfer_nbtc(&account_id, amount)
}
``` [2](#0-1) 

**2. `execute_refund`** — the sole mechanism to initiate the on-chain BTC return for a deposit that was never finalized via `verify_deposit`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
``` [3](#0-2) 

The `lost_found` ledger is populated when a withdrawal cancellation's nBTC refund transfer fails. The `refund_requests` map is populated by `request_refund`. Both of these states can exist on-chain before a pause event. Once the contract is paused, neither `claim_lost_found` nor `execute_refund` can be called by any non-DAO account, leaving the user's funds inaccessible for an indefinite period.

Critically, `PauseManager` and `UnpauseManager` are **separate roles**: [4](#0-3) 

The entity that pauses cannot unpause. If the `UnpauseManager` key is unavailable or slow to respond, the lockout is extended.

---

### Impact Explanation

- **`claim_lost_found` blocked**: A user whose nBTC was routed to `lost_found` (a real, non-exceptional path when the nBTC token storage is not registered at the time of a cancel-withdraw refund) cannot recover their nBTC. The tokens remain locked inside the bridge contract's `lost_found` map.
- **`execute_refund` blocked**: A user who deposited BTC on-chain but whose deposit was never finalized (relayer failure, light-client lag, etc.) and who has a valid `RefundRequest` on-chain cannot trigger the MPC-signed BTC return. Their BTC remains locked in the MPC-controlled deposit address.

Both cases constitute **stuck bridge state requiring operator intervention** — a Medium impact per the allowed scope. In the worst case (extended or permanent pause), the impact escalates toward permanent loss of user funds.

---

### Likelihood Explanation

The `PauseManager` role is granted to every super-admin at creation time and is a standard operational tool for emergency response. Any legitimate pause event — security incident, upgrade preparation, oracle failure — immediately and silently blocks all users who happen to have funds in `lost_found` or pending `refund_requests` at that moment. No malicious intent is required; the collision between a routine pause and a user's recovery attempt is a realistic operational scenario, directly analogous to the confirmed WardenPledge finding.

---

### Recommendation

Remove the pause guard from `claim_lost_found` and `execute_refund`, or add an explicit exception for the fund owner (analogous to `except(roles(Role::DAO))`). These functions only return funds that are already committed and owed to the user — they do not introduce new risk that a pause is designed to mitigate. Alternatively, route the pause through a timelock governance contract so users have advance notice and can complete in-flight recovery calls before the pause takes effect.

---

### Proof of Concept

**Scenario A — `claim_lost_found` blocked:**

1. User initiates a withdrawal via `ft_transfer_call` → `ft_on_transfer` → `BTCPendingInfo` created.
2. Operator calls `cancel_withdraw`; the bridge attempts to return nBTC but the transfer fails (user's token storage not registered) → nBTC amount is written to `data.lost_found[user]`.
3. `PauseManager` pauses the contract (legitimate emergency action, takes effect immediately).
4. User calls `claim_lost_found` → transaction panics with "Contract is paused" because of `#[pause(except(roles(Role::DAO)))]`.
5. User's nBTC remains locked in `lost_found` until `UnpauseManager` acts.

**Scenario B — `execute_refund` blocked:**

1. User sends BTC to the bridge deposit address derived from their `DepositMsg`.
2. The deposit is never finalized (relayer outage). User calls `request_refund` with a valid SPV proof → `RefundRequest` stored on-chain.
3. Timelock elapses. User (or anyone) attempts `execute_refund`.
4. `PauseManager` pauses the contract before the call lands.
5. `execute_refund` panics with "Contract is paused" — the MPC-signed BTC return transaction is never constructed.
6. User's BTC remains locked in the MPC-controlled deposit address until the contract is unpaused. [2](#0-1) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L161-163)
```rust
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L44-51)
```rust
        let is_success = self
            .acl_grant_role(Role::PauseManager.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_grant_role PauseManager failed");
        let is_success = self
            .acl_grant_role(Role::UnpauseManager.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_grant_role UnpauseManager failed");
```
