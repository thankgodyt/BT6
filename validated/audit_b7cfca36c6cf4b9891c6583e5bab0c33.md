### Title
Pause Mechanism Blocks Critical User-Protective Functions `execute_refund` and `claim_lost_found`, Temporarily Locking User Funds - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The `satoshi-bridge` contract applies `#[pause(except(roles(Role::DAO)))]` to `execute_refund` and `claim_lost_found`, which are the primary mechanisms for users to recover their BTC and nBTC respectively. When the protocol is paused, users with pending refund requests cannot execute their BTC refunds, and users with nBTC in `lost_found` cannot retrieve their tokens, resulting in temporary locking of user funds.

### Finding Description
The bridge implements a pause mechanism via `near-plugins`' `Pausable` trait, controlled by the `PauseManager` role. [1](#0-0) 

When paused, only the DAO role can bypass the restriction. The following user-protective functions are blocked during a pause:

**1. `execute_refund`** — Users who have submitted a refund request (for BTC sent to the bridge that could not be processed) cannot execute the refund to recover their BTC. [2](#0-1) 

**2. `claim_lost_found`** — Users who have nBTC stuck in the `lost_found` map (from failed `cancel_withdraw` refund transfers) cannot retrieve their tokens. [3](#0-2) 

Both functions are critical for users to recover funds already committed to the bridge. The `execute_refund` path is particularly relevant: a user who has sent BTC to the bridge, submitted a `request_refund`, and waited through the timelock (default 2 days for pre-authorized addresses, 14 days for unsafe addresses) is completely blocked from recovering their BTC during a pause. [4](#0-3) 

The `lost_found` path is triggered when a `cancel_withdraw` operation successfully cancels a withdrawal but the nBTC transfer back to the user fails (e.g., insufficient storage deposit). The nBTC is held in the contract's `lost_found` map and can only be retrieved via `claim_lost_found`. [5](#0-4) 

### Impact Explanation
Medium. During a pause, users cannot recover their BTC via `execute_refund` or their nBTC via `claim_lost_found`. This results in temporary locking of user funds — BTC held at bridge-controlled MPC addresses and nBTC held in the contract's `lost_found` map. No permanent loss occurs, but users are unable to access their own funds until the pause is lifted, constituting a stuck bridge state requiring operator intervention (unpausing). This matches the "stuck bridge state requiring operator intervention" impact class.

### Likelihood Explanation
Low. Protocol pauses are rare events triggered by the `PauseManager` role in emergency scenarios. However, the impact during such events is significant for any user who has a pending refund request past its timelock or nBTC sitting in `lost_found`.

### Recommendation
Remove the `#[pause]` decorator from `execute_refund` and `claim_lost_found`, or add these functions to a bypass-roles exception list, so users can always recover their own committed funds regardless of pause state:

```diff
  #[payable]
- #[pause(except(roles(Role::DAO)))]
+ #[pause(except(roles(Role::DAO, Role::PauseManager)))]  // or remove entirely
  pub fn execute_refund(
      &mut self,
      utxo_storage_key: String,
      chain_specific_data: Option<ChainSpecificData>,
  ) -> PromiseOrValue<()> {

  #[payable]
- #[pause(except(roles(Role::DAO)))]
  pub fn claim_lost_found(&mut self) -> Promise {
```

### Proof of Concept

**Scenario A — Temporary locking of BTC via `execute_refund`:**
1. User sends BTC to the bridge deposit address with incorrect metadata (or for any reason requiring a refund).
2. User calls `request_refund` with a valid `TxInclusionProof`, paying the required storage deposit. [6](#0-5) 
3. The refund timelock passes (minimum 2 days for pre-authorized, 14 days for unsafe). [7](#0-6) 
4. The `PauseManager` pauses the protocol.
5. User calls `execute_refund` — the call reverts due to the `#[pause]` guard.
6. User's BTC remains locked at the bridge-controlled MPC address until the pause is lifted. The user has no alternative recovery path.

**Scenario B — Temporary locking of nBTC via `claim_lost_found`:**
1. User initiates a withdrawal via `ft_on_transfer`, transferring nBTC to the bridge. [8](#0-7) 
2. Operator calls `cancel_withdraw` to cancel the withdrawal; the bridge attempts to refund nBTC to the user but the transfer fails (e.g., user has no storage).
3. The nBTC is placed in `lost_found` for the user.
4. The `PauseManager` pauses the protocol.
5. User calls `claim_lost_found` — the call reverts due to the `#[pause]` guard.
6. User's nBTC remains locked in `lost_found` until the pause is lifted, with no alternative recovery mechanism available to the user.

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L140-140)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/refund.rs (L244-248)
```rust
        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L22-28)
```rust
    #[pause(except(roles(Role::DAO)))]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
```
