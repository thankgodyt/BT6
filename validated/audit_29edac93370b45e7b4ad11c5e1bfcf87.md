### Title
Overly Restrictive Pause Guard Permanently Freezes User nBTC Stuck in `lost_found` - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `claim_lost_found` function, which is the sole recovery path for nBTC already committed to the bridge but stranded after a failed refund transfer, is gated by `#[pause(except(roles(Role::DAO)))]`. When the bridge is paused, ordinary users cannot recover these funds even though the operation requires no price oracle, no new minting, and no external validation — it is a pure internal bookkeeping transfer of already-committed assets.

### Finding Description
The withdrawal cancellation flow works as follows:

1. User calls `ft_on_transfer` (via `ft_transfer_call`) to transfer nBTC to the bridge and initiate a withdrawal.
2. An operator or the user calls `cancel_withdraw`, which triggers `internal_transfer_nbtc` to refund the nBTC back to the user.
3. If that `ft_transfer` cross-contract call fails (e.g., user lacks NEP-141 storage registration), `transfer_nbtc_callback` stores the amount in `data.lost_found[account_id]` instead of reverting.
4. The user must then call `claim_lost_found` to recover their nBTC.

`claim_lost_found` is decorated with `#[pause(except(roles(Role::DAO)))]`:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 449-460
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

When the bridge is paused, this function panics for any non-DAO caller. The nBTC recorded in `lost_found` is already fully owned by the user — it was transferred to the bridge, the withdrawal was cancelled, and the bridge already attempted to return it. No new minting, no oracle price, no UTXO state, and no external dependency is involved in `claim_lost_found`. The pause guard is therefore entirely unnecessary for this function and causes user funds to be frozen for the entire duration of any pause.

The `transfer_nbtc_callback` that populates `lost_found` is itself a `#[private]` callback and cannot be blocked by pause, meaning funds can enter `lost_found` even during a pause (e.g., if a cancel_withdraw was in-flight when the pause was applied), but the only exit path is blocked.

### Impact Explanation
Any user whose nBTC lands in `lost_found` while the bridge is paused — or who had funds there before the pause — has their nBTC permanently frozen for the duration of the pause. The bridge has no enforced unpause deadline; a pause can last indefinitely. The user accumulates no interest (unlike H-5), but their nBTC is irrecoverable without DAO intervention to either unpause or manually transfer. This constitutes temporary-to-permanent locking of bridged user funds with no self-service remedy.

### Likelihood Explanation
Any bridge pause event (triggered by any account holding `Role::PauseManager`) immediately activates this freeze for all users with a `lost_found` balance. The `lost_found` path is a documented, expected fallback for failed refund transfers, so affected users are a realistic population. Pauses are a routine operational tool (e.g., for upgrades or incident response), making the combination likely over the bridge's lifetime.

### Recommendation
Remove the `#[pause]` guard from `claim_lost_found`. The function only reads from `data.lost_found` and calls `internal_transfer_nbtc` — both are pure internal operations that return already-committed user funds. There is no security rationale for blocking this during a pause. Analogously to the H-5 fix (moving `_checkIfCollateralIsActive` inside the branch that actually needs it), `claim_lost_found` should be unconditionally callable by the fund owner:

```rust
// Remove #[pause(except(roles(Role::DAO)))]
#[payable]
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

### Proof of Concept
1. User Alice calls `ft_transfer_call` on the nBTC contract, transferring 1 nBTC to the bridge with a `Withdraw` message. The bridge records a `BTCPendingInfo`.
2. An operator calls `cancel_withdraw`. The bridge calls `internal_transfer_nbtc` to return Alice's nBTC.
3. Alice's nBTC storage registration has lapsed. The `ft_transfer` cross-contract call fails. `transfer_nbtc_callback` fires and stores `1 nBTC` in `data.lost_found[alice]`.
4. A `PauseManager` pauses the bridge (e.g., for a routine upgrade).
5. Alice calls `claim_lost_found`. The `#[pause]` macro fires before any contract logic and panics: `"Contract is paused"`.
6. Alice's 1 nBTC remains locked in `data.lost_found` for the entire pause duration with no self-service recovery path. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L53-74)
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
```

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```
