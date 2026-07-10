### Title
Paused Bridge Blocks Users from Claiming Already-Credited `lost_found` nBTC - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `claim_lost_found` function in the `satoshi-bridge` contract is gated by `#[pause(except(roles(Role::DAO)))]`. When the bridge is paused, users whose nBTC was already credited into the `lost_found` map (due to a failed `ft_transfer` callback) are permanently blocked from reclaiming those funds until the DAO manually unpauses the contract.

### Finding Description
When an nBTC transfer initiated by the bridge fails (e.g., during a cancel-withdraw refund), `transfer_nbtc_callback` in `token_transfer.rs` credits the owed amount into `data.lost_found[account_id]` rather than losing it: [1](#0-0) 

The user's only recovery path is `claim_lost_found`: [2](#0-1) 

This function carries `#[pause(except(roles(Role::DAO)))]` at line 450. The `near-plugins` `Pausable` macro causes the entire call to revert when the contract is paused and the caller is not the DAO. Because the nBTC is already removed from the user's account and credited inside the bridge's own storage, the user has no alternative mechanism to retrieve it. The funds sit locked in `data.lost_found` for the entire duration of the pause. [3](#0-2) 

### Impact Explanation
Any user who has a non-zero balance in `data.lost_found` is unable to access their nBTC while the bridge is paused. The nBTC is already minted and held by the bridge contract on their behalf; the pause does not protect any new operation — it only blocks the user's sole recovery path. This constitutes a stuck bridge state requiring operator (DAO) intervention to unpause before users can reclaim their own funds.

**Allowed impact matched:** Medium — stuck bridge state requiring operator intervention; attacker-triggered temporary locking of bridged funds (a malicious or negligent DAO pause directly locks user funds with no user-side remedy).

### Likelihood Explanation
Bridge pauses are a routine operational event (maintenance, upgrades, incident response). The `lost_found` map is populated whenever any `internal_transfer_nbtc` call fails, which can happen due to insufficient storage registration on the nBTC contract — a condition that is not rare. The combination of a routine pause and a failed transfer callback is a realistic, reachable scenario for any ordinary bridge user.

### Recommendation
Remove the `#[pause(except(roles(Role::DAO)))]` guard from `claim_lost_found`. Claiming already-credited funds is a pure user-recovery operation that carries no new risk when the bridge is paused; it does not mint new tokens, does not accept new deposits, and does not interact with the light client or MPC. Isolate the pause guard to operations that introduce new cross-chain state (deposits, withdrawals, refund execution), mirroring the fix recommended in the reference report.

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message → bridge creates a pending withdrawal.
2. DAO calls `cancel_withdraw`, which eventually calls `internal_transfer_nbtc` to refund the user's nBTC.
3. The `ft_transfer` to the user fails (e.g., user's nBTC storage is not registered).
4. `transfer_nbtc_callback` fires and credits `data.lost_found[user] += amount`. [4](#0-3) 

5. DAO pauses the bridge for any routine reason (upgrade, incident).
6. User calls `claim_lost_found` → the `#[pause]` macro reverts the call with a "paused" error. [2](#0-1) 

7. User's nBTC remains locked in `data.lost_found` with no alternative recovery path until the DAO unpauses the contract. [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/lib.rs (L140-140)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
```
