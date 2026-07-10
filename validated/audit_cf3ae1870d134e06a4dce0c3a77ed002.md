### Title
`claim_lost_found` Blocked by Pause Guard, Permanently Locking User nBTC During Contract Pause — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The `claim_lost_found` function, which is the sole recovery path for nBTC tokens already credited to users in the `lost_found` map, is gated by `#[pause(except(roles(Role::DAO)))]`. When the contract is paused, ordinary users cannot call this function and their already-credited nBTC tokens are stuck until an operator unpauses the contract.

### Finding Description
When a `cancel_withdraw` RBF is verified on-chain, the bridge attempts to refund the remaining nBTC to the user via `internal_transfer_nbtc`. If that cross-contract call fails (e.g., user's nBTC storage is not registered), the callback `transfer_nbtc_callback` credits the amount into `data.lost_found[account_id]` instead of reverting: [1](#0-0) 

The only way for a user to recover these tokens is `claim_lost_found`: [2](#0-1) 

This function carries `#[pause(except(roles(Role::DAO)))]`, meaning when the contract is paused (by a `PauseManager`), all non-DAO callers receive `"Method is paused"` and cannot retrieve their funds. The tokens are already debited from the bridge's withdrawal flow and credited to the user in `lost_found` — they belong to the user — but the user has no alternative recovery path. [3](#0-2) 

### Impact Explanation
User nBTC tokens that have already been credited to `lost_found` are stuck for the entire duration of the pause. The user cannot recover them without DAO/operator intervention to unpause the contract. This matches the **Medium** impact class: attacker-triggered (or incidental) temporary locking of bridged funds, and a stuck bridge state requiring operator intervention.

### Likelihood Explanation
**Medium.** Two conditions must coincide: (1) a user has a non-zero `lost_found` balance (requires a failed `ft_transfer` callback during `cancel_withdraw` finalization), and (2) the contract is paused. Both are realistic operational scenarios — storage failures are a known NEAR edge case, and the bridge has explicit pause infrastructure used during upgrades or security incidents.

### Recommendation
Remove `#[pause(except(roles(Role::DAO)))]` from `claim_lost_found`. The function only transfers tokens already credited to the caller; it introduces no new risk surface and should remain callable regardless of pause state, analogous to how emergency-exit functions in other bridge designs must bypass pause guards.

### Proof of Concept

1. User initiates a withdrawal via `ft_transfer_call` → bridge constructs BTC tx.
2. DAO/Operator calls `cancel_withdraw` after timeout; a cancel-RBF PSBT is signed and broadcast.
3. Relayer calls `verify_withdraw_v2` for the cancel-RBF tx; `verify_withdraw_callback` succeeds.
4. Bridge calls `internal_transfer_nbtc(user, refund_amount)`.
5. The `ft_transfer` cross-contract call fails (user's nBTC account not registered for storage).
6. `transfer_nbtc_callback` fires: `lost_found[user] += refund_amount`. [4](#0-3) 

7. A `PauseManager` pauses the contract (`pa_pause_feature("ALL")`).
8. User calls `claim_lost_found()` → **panics with `"Method is paused"`**.
9. User's nBTC is stuck in `lost_found` until DAO unpauses. [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L53-75)
```rust
    #[private]
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
    }
```

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
