### Title
Unguarded State Mutation Before Cross-Contract Call in `claim_lost_found` Permanently Destroys User Funds on Transfer Failure - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

`claim_lost_found` removes a user's entry from the `lost_found` map before the nBTC `ft_transfer` cross-contract call is confirmed. Because NEAR commits state changes when the function returns (not when the downstream promise resolves), any failure of the `internal_transfer_nbtc` promise permanently destroys the user's recovery entry with no rollback path and no operator-visible accounting trail.

### Finding Description

`claim_lost_found` is the designated last-resort recovery function for users whose nBTC refund transfer failed during a cancel-withdraw RBF flow. Its implementation is: [1](#0-0) 

```rust
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data_mut()
        .lost_found
        .remove(&account_id)          // ← state committed on function return
        .expect("The account does not have lostfound");
    self.internal_transfer_nbtc(&account_id, amount)  // ← no failure callback
}
```

In NEAR's execution model, state mutations applied inside a `#[near]` function that returns a `Promise` are committed to storage when the function returns — not when the returned promise resolves. There is no automatic rollback if the downstream promise fails.

`internal_transfer_nbtc` issues an `ft_transfer` call to the nBTC contract. This call can fail for several realistic reasons:

1. **nBTC contract is paused** — the bridge's own `#[pause]` guard protects `claim_lost_found`, but the nBTC contract has its own independent pause mechanism. A security incident that pauses nBTC while the bridge remains live is a realistic operational scenario.
2. **Recipient account not registered in nBTC** — NEP-141 requires storage registration. After a token migration (`migrate_to_new_token` exists in the codebase), a user's account may not be registered in the new nBTC contract.
3. **Any other nBTC-side rejection** — contract upgrade bugs, storage exhaustion, etc.

When the transfer fails:
- `lost_found.remove` is already committed — the entry is gone.
- The bridge still holds the nBTC in its own balance (the transfer never executed), but there is no on-chain record linking those tokens to the user.
- `claim_lost_found` has no callback and no fallback re-insertion into `lost_found`.
- The user cannot call `claim_lost_found` again (the entry no longer exists).

The bridge's nBTC balance is now inflated relative to what it owes users — a supply/accounting invariant violation directly analogous to the Umee report's concern about `tokenSupply` diverging from `uTokenSupply` when intermediate state is not properly guarded.

The contrast with the correct pattern used elsewhere in the codebase is instructive. The `verify_withdraw_burn_callback` explicitly rolls back state on failure: [2](#0-1) 

```rust
} else {
    self.internal_unwrap_mut_btc_pending_info(&tx_id)
        .to_pending_verify_stage();
}
```

No equivalent rollback exists in `claim_lost_found`.

### Impact Explanation

**Medium.** When the nBTC transfer fails, the user's `lost_found` balance is permanently erased from contract state. The bridge retains the corresponding nBTC in its own balance with no accounting entry, creating a silent surplus. The user has no permissionless recovery path; operator intervention (manual identification of the orphaned balance and a privileged re-credit) is required. This matches the allowed impact class: *broken callback rollback / stuck bridge state requiring operator intervention* and *permanent burning below backed supply* (from the user's perspective, their nBTC is destroyed).

### Likelihood Explanation

**Low.** The failure condition requires the nBTC `ft_transfer` to be rejected at the moment `claim_lost_found` is called. The most realistic triggers are: (a) the nBTC contract being paused during a concurrent security incident while the bridge remains live, or (b) a token migration leaving the user's account unregistered in the new nBTC contract. Neither is an everyday occurrence, but both are operationally plausible and require no attacker capability — a legitimate user calling the function at the wrong moment is sufficient.

### Recommendation

Apply the Checks-Effects-Interactions pattern correctly: do not remove the `lost_found` entry until the transfer is confirmed. Add a `#[private]` callback:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data()
        .lost_found
        .get(&account_id)
        .copied()
        .expect("The account does not have lostfound");
    // Do NOT remove yet — remove only in the success callback
    self.internal_transfer_nbtc(&account_id, amount)
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_CLAIM_LOST_FOUND_CALLBACK)
                .claim_lost_found_callback(account_id, amount),
        )
}

#[private]
pub fn claim_lost_found_callback(&mut self, account_id: AccountId, amount: u128) -> bool {
    if is_promise_success() {
        self.data_mut().lost_found.remove(&account_id);
        true
    } else {
        // Entry remains in lost_found; user can retry
        false
    }
}
```

### Proof of Concept

1. User Alice has a `lost_found` entry of 100,000 satoshis (created when a cancel-withdraw RBF refund transfer failed).
2. A security incident causes the nBTC contract to be paused.
3. Alice calls `claim_lost_found` with 1 yoctoNEAR attached.
4. The contract executes: `lost_found.remove(&alice)` — state committed, entry gone.
5. `internal_transfer_nbtc(&alice, 100_000)` schedules an `ft_transfer` on the paused nBTC contract.
6. The nBTC contract rejects the call (paused). Promise fails.
7. No callback exists to re-insert Alice's entry.
8. Alice calls `claim_lost_found` again → panics: "The account does not have lostfound".
9. Alice's 100,000 satoshi-equivalent nBTC is permanently orphaned in the bridge's balance. The bridge's nBTC holdings exceed the sum of all user-claimable balances by 100,000 satoshis — a reachable supply accounting invariant violation with no permissionless remedy.

### Citations

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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L149-152)
```rust
        } else {
            self.internal_unwrap_mut_btc_pending_info(&tx_id)
                .to_pending_verify_stage();
        }
```
