### Title
Permanent Loss of User Funds in `claim_lost_found` Due to Missing Failure Callback — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`claim_lost_found` removes the user's entry from the `lost_found` map before the cross-contract nBTC transfer promise resolves. In NEAR Protocol, state mutations committed before returning a `Promise` are **not rolled back** if the promise fails. Because there is no `.then()` failure-handling callback, any failure of the nBTC transfer (e.g., nBTC contract paused, user storage not registered) permanently destroys the user's recovery entry with no recourse.

---

### Finding Description

In `contracts/satoshi-bridge/src/api/bridge.rs` lines 451–460:

```rust
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data_mut()
        .lost_found
        .remove(&account_id)          // ← state change committed immediately
        .expect("The account does not have lostfound");
    self.internal_transfer_nbtc(&account_id, amount)  // ← Promise returned, no .then() callback
}
```

The function:
1. **Removes** the user's amount from `lost_found` — this state change is committed to storage the moment the function returns, regardless of what the returned `Promise` does.
2. **Returns** a bare `Promise` for the cross-contract nBTC transfer with **no `.then()` callback** to handle failure.

In NEAR's execution model, state mutations made in a function body are finalized when the function returns. Only a panic within the same call frame rolls them back. A subsequent cross-contract call failure does **not** revert the caller's already-committed state. Therefore, if `internal_transfer_nbtc` fails for any reason, the `lost_found` entry is gone and the nBTC tokens remain locked inside the bridge contract with no recovery path for the user.

The analog to the Kodiak report is direct:
- **Kodiak**: `claim()` calls `kodiakFarm.getReward()` which reverts when paused → rewards stuck in adapter, no recovery.
- **Bridge**: `claim_lost_found()` removes the `lost_found` entry then calls `internal_transfer_nbtc()` which can fail when the nBTC contract is paused or storage is missing → user's nBTC permanently lost, no recovery.

The `lost_found` map is explicitly described in the comment at line 448 as the recovery mechanism for failed refunds: *"Cancel Withdraw will refund the remaining nBTC to the user. If the refund fails, the user can retrieve it again through this interface."* Destroying that entry without a confirmed successful transfer eliminates the only recovery path. [1](#0-0) 

---

### Impact Explanation

**Critical — Permanent loss of user funds.**

The nBTC tokens remain inside the bridge contract (they are not burned), but the `lost_found` accounting entry is deleted. There is no operator-callable rescue function, no re-insertion path, and no event that would allow off-chain tooling to reconstruct the lost state. The user's funds are permanently inaccessible. [2](#0-1) 

---

### Likelihood Explanation

**Medium.**

The nBTC contract is a separate deployed contract. Conditions that cause `internal_transfer_nbtc` to fail include:

- The nBTC contract being paused (the bridge itself has a `Pausable` plugin; the nBTC contract is a separate NEP-141 implementation that may have its own pause).
- The recipient account not having storage registered on the nBTC contract (a common NEP-141 failure mode).
- The nBTC contract being mid-migration or upgrade.

Any of these conditions can be triggered independently of the bridge's own pause state, and the `lost_found` path is specifically reached after a prior failure (e.g., a failed `cancel_withdraw` refund), meaning the user is already in a degraded state when they call `claim_lost_found`. [3](#0-2) 

---

### Recommendation

Add a `.then()` callback that re-inserts the amount into `lost_found` on transfer failure, mirroring the pattern that populates `lost_found` in the first place:

```rust
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data_mut()
        .lost_found
        .remove(&account_id)
        .expect("The account does not have lostfound");
    self.internal_transfer_nbtc(&account_id, amount)
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_CLAIM_LOST_FOUND_CALLBACK)
                .claim_lost_found_callback(account_id, amount),
        )
}

#[private]
pub fn claim_lost_found_callback(&mut self, account_id: AccountId, amount: u128) {
    if !is_promise_success() {
        // Re-insert so the user can try again
        self.data_mut().lost_found.insert(account_id, amount);
    }
}
```

This is the exact pattern recommended in the Kodiak report (wrapping the external call so failure is handled gracefully rather than silently destroying state).

---

### Proof of Concept

1. User's nBTC ends up in `lost_found` after a failed `cancel_withdraw` refund transfer (the intended recovery path).
2. The nBTC contract is paused for any reason (upgrade, emergency, governance action), **or** the user has not registered storage on the nBTC contract.
3. User calls `claim_lost_found` with 1 yoctoNEAR attached.
4. `self.data_mut().lost_found.remove(&account_id)` executes and the state change is committed — the entry is gone.
5. `internal_transfer_nbtc` issues a cross-contract call to the nBTC contract; the call fails (paused / no storage).
6. NEAR does **not** roll back the `lost_found.remove()` — the entry remains deleted.
7. The user's nBTC is now locked inside the bridge contract forever: no `lost_found` entry to claim, no other recovery function exists. [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L448-460)
```rust
    /// Cancel Withdraw will refund the remaining nBTC to the user. If the refund fails, the user can retrieve it again through this interface.
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

**File:** contracts/satoshi-bridge/src/lib.rs (L5-5)
```rust
    env, ext_contract, is_promise_success,
```

**File:** contracts/satoshi-bridge/src/lib.rs (L140-140)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
```
