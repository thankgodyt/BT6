### Title
Missing Pause Guard on nBTC Token Contract Allows Token Transfers and Legacy Withdrawal Redirection During Bridge Emergency Pause - (File: contracts/nbtc/src/lib.rs)

### Summary
The `satoshi-bridge` contract derives `Pausable` and applies `#[pause(except(roles(Role::DAO)))]` to every critical public function. The `nbtc` token contract, however, has no `Pausable` implementation at all. As a result, `ft_transfer` and `ft_transfer_call` remain fully callable by any token holder even when the bridge is paused. The most concrete impact is the legacy `WITHDRAW_TO:` path inside `ft_transfer`: it silently redirects tokens to the `withdraw_relayer` account without any callback or rollback, permanently removing them from the sender's balance while the bridge is unable to process the corresponding withdrawal.

### Finding Description
`contracts/satoshi-bridge/src/lib.rs` derives `Pausable` and configures pause/unpause roles:

```rust
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
pub struct Contract { ... }
```

Every public entry point on the bridge carries `#[pause(except(roles(Role::DAO)))]` — `verify_deposit`, `ft_on_transfer`, `verify_withdraw`, `execute_refund`, `sign_btc_transaction`, `claim_lost_found`, etc.

`contracts/nbtc/src/lib.rs` has no such derivation:

```rust
#[derive(PanicOnDefault)]   // no Pausable
#[near(contract_state)]
pub struct Contract {
    controller: AccountId,
    bridge_id: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
```

No `#[pause]` attribute appears anywhere in the nbtc contract. The `FungibleTokenCore` implementation exposes two unguarded public entry points:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // Legacy bridging flow used by Near Intents
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);  // direct transfer, no callback
        }
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}

fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>, msg: String)
    -> PromiseOrValue<U128> {
    self.token.ft_transfer_call(receiver_id, amount, memo, msg)
}
```

The `WITHDRAW_TO:` branch in `ft_transfer` is the critical path. It performs a raw `internal_transfer` to the `withdraw_relayer` address with no XCC callback and no rollback mechanism. Unlike `ft_transfer_call` (where a panicking `ft_on_transfer` on the paused bridge causes the NEP-141 resolver to refund the sender), this direct transfer is final and irreversible at the contract level.

### Impact Explanation
When the bridge is paused due to an emergency, any nBTC holder can call:

```
nbtc.ft_transfer(
    receiver_id = nbtc_contract_id,
    amount      = X,
    memo        = "WITHDRAW_TO:<btc_address>"
)
```

The nbtc contract immediately executes `self.token.ft_transfer(withdraw_relayer, X, memo)`. The tokens leave the caller's balance and land in the withdraw_relayer's account. Because the bridge is paused, no withdrawal can be processed. The tokens are stuck in the withdraw_relayer's account and require operator intervention to recover, constituting a stuck bridge state. More broadly, the governance cannot freeze nBTC token movements during an emergency, undermining the entire purpose of the pause mechanism.

This matches the allowed impact: **Medium — Bypass of bridge limits or policies; attacker-triggered stuck bridged funds requiring operator intervention.**

### Likelihood Explanation
Any nBTC holder can trigger this with a single transaction at any time the bridge is paused. No special role, leaked key, or privileged access is required. The `WITHDRAW_TO:` memo path is a documented, publicly reachable feature ("Legacy bridging flow used by Near Intents"). Likelihood is **Medium**: the bridge must be paused for the bypass to matter, but once paused the path is trivially reachable.

### Recommendation
Add `Pausable` to the nbtc contract and guard `ft_transfer` and `ft_transfer_call` with a pause check, mirroring the pattern used in `satoshi-bridge`:

```rust
#[derive(Pausable, PanicOnDefault)]
#[near(contract_state)]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
pub struct Contract { ... }
```

```rust
#[pause(except(roles(Role::DAO)))]
fn ft_transfer(&mut self, ...) { ... }

#[pause(except(roles(Role::DAO)))]
fn ft_transfer_call(&mut self, ...) -> PromiseOrValue<U128> { ... }
```

At minimum, the `WITHDRAW_TO:` branch inside `ft_transfer` must be gated so that the legacy withdrawal redirection cannot proceed while the bridge is paused.

### Proof of Concept
1. PauseManager pauses the `satoshi-bridge` contract (emergency scenario).
2. Attacker (any nBTC holder) submits:
   ```
   nbtc.ft_transfer(
       receiver_id = "nbtc.near",        // nbtc contract itself
       amount      = "1000000",
       memo        = "WITHDRAW_TO:bc1qattacker..."
   )
   ```
3. `ft_transfer` in `contracts/nbtc/src/lib.rs` lines 185–192 matches the condition and calls `self.token.ft_transfer(withdraw_relayer, 1000000, memo)`.
4. Tokens are debited from the attacker's balance and credited to `withdraw_relayer`. No callback is issued; the transfer is final.
5. The bridge is paused — `ft_on_transfer` on `satoshi-bridge` carries `#[pause(except(roles(Role::DAO)))]` and will reject any subsequent call. The withdrawal cannot be processed.
6. The 1,000,000 satoshi-equivalent nBTC are stuck in the withdraw_relayer's account until an operator manually recovers them, requiring privileged intervention to restore the bridge to a consistent state. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L22-29)
```rust
#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct Contract {
    controller: AccountId,
    bridge_id: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
```

**File:** contracts/nbtc/src/lib.rs (L37-38)
```rust
const WITHDRAW_RELAYER_ADDRESS: &[u8] = b"WITHDRAW_RELAYER_ADDRESS";
const WITHDRAW_MEMO_PREFIX: &str = "WITHDRAW_TO:";
```

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L198-207)
```rust
    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L22-23)
```rust
    #[pause(except(roles(Role::DAO)))]
    fn ft_on_transfer(
```
