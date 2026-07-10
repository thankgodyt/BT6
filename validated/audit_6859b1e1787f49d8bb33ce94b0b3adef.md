### Title
`claim_lost_found` Blocked by Bridge Pause Leaves User nBTC Temporarily Stuck — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `claim_lost_found` function is gated by the bridge-wide `#[pause]` decorator. When the bridge is paused, users whose nBTC already resides in the `lost_found` accounting map cannot retrieve it. This breaks the protocol's recovery invariant: funds already credited to `lost_found` should always be redeemable, yet the pause silently blocks the only public exit path for those funds.

---

### Finding Description

When an nBTC transfer back to a user fails (e.g., the recipient has no storage registered on the token contract), `transfer_nbtc_callback` credits the amount to the `lost_found` map instead of reverting: [1](#0-0) 

The designated recovery path is `claim_lost_found`: [2](#0-1) 

However, `claim_lost_found` carries `#[pause(except(roles(Role::DAO)))]`. When the bridge is paused by any `PauseManager`, the function reverts for all non-DAO callers. The nBTC is already held in the bridge's accounting — it is not in transit, not locked in a pending withdrawal, and not recoverable through any other public function — yet the pause prevents its withdrawal.

This is structurally identical to the Kodiak finding: an intermediate contract holds assets that belong to users, and the only forwarding path is blocked by a pause flag, leaving the assets stuck until an operator acts.

---

### Impact Explanation

Users whose nBTC ended up in `lost_found` (e.g., after a cancelled withdrawal where the refund transfer failed) are unable to reclaim their tokens for the entire duration of any bridge pause. The funds are not permanently lost, but they are inaccessible without operator intervention (unpausing), matching the **Medium — attacker-triggered or operator-triggered temporary locking of bridged funds** impact category.

---

### Likelihood Explanation

Two independent conditions must coincide:

1. A user's nBTC transfer fails and lands in `lost_found` — a realistic scenario whenever a recipient account lacks token-storage registration.
2. The bridge is paused — a legitimate operational action available to any `PauseManager`.

Neither condition is exotic; both are part of normal bridge operation. Likelihood is **Medium**.

---

### Recommendation

Exempt `claim_lost_found` from the pause, analogously to how DAO operations are already exempted elsewhere:

```rust
// Before
#[pause(except(roles(Role::DAO)))]
pub fn claim_lost_found(&mut self) -> Promise {

// After — allow any user to reclaim their own already-credited funds
#[pause(except(roles(Role::DAO, Role::UnpauseManager)))]  // or remove #[pause] entirely
pub fn claim_lost_found(&mut self) -> Promise {
```

Alternatively, model the fix after the Kodiak recommendation: ensure the recovery path is never blocked by an external or internal pause state, since the funds are already inside the contract's accounting.

---

### Proof of Concept

1. User calls `ft_transfer_call` on nBTC → bridge's `ft_on_transfer` initiates a withdrawal.
2. Withdrawal is later cancelled; bridge calls `internal_transfer_nbtc` to refund the user.
3. `ft_transfer` on the nBTC contract fails (user has no storage) → `transfer_nbtc_callback` writes the amount into `lost_found`. [3](#0-2) 
4. A `PauseManager` pauses the bridge (legitimate operational action).
5. User calls `claim_lost_found` → transaction reverts because `#[pause]` is active. [4](#0-3) 
6. No other public function allows the user to retrieve their nBTC.
7. Funds remain stuck in `lost_found` until the bridge is unpaused by an operator.

### Citations

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-74)
```rust
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
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
