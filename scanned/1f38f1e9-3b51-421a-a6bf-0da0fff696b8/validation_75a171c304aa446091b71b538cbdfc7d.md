### Title
`TokenLockController` Can Arbitrarily Overwrite Locked-Token Accounting, Permanently Freezing Bridged User Funds - (File: near/omni-bridge/src/token_lock.rs)

### Summary

The `set_locked_tokens` function in `near/omni-bridge/src/token_lock.rs` grants the `TokenLockController` role unconstrained write access to the `locked_tokens` map — the sole escrow-accounting ledger that guards whether pending cross-chain transfers can be finalized. A holder of this role can set any chain/token pair's locked balance to an arbitrary value (including zero), silently breaking the invariant that `locked_tokens[chain][token] ≥ Σ pending transfer amounts`. This is the direct analog of the external report's "manager can manipulate positions at the user's detriment" finding.

### Finding Description

`set_locked_tokens` is a public, role-gated function that performs a raw `insert` into `self.locked_tokens` with no validation against the actual sum of in-flight transfers:

```rust
// near/omni-bridge/src/token_lock.rs  lines 38-44
#[access_control_any(roles(Role::DAO, Role::TokenLockController))]
pub fn set_locked_tokens(&mut self, args: Vec<SetLockedTokenArgs>) {
    for arg in args {
        self.locked_tokens
            .insert(&(arg.chain_kind, arg.token_id), &arg.amount.0);
    }
}
``` [1](#0-0) 

The `locked_tokens` map is the only on-chain record of how many tokens are committed to pending outbound transfers for each `(ChainKind, token_id)` pair. Every finalization path reads this map and enforces the invariant via `unlock_tokens`:

```rust
// near/omni-bridge/src/token_lock.rs  lines 71-94
fn unlock_tokens(...) {
    let Some(available) = self.locked_tokens.get(&key) else {
        return LockAction::Unchanged;
    };
    require!(
        available >= amount,
        TokenLockError::InsufficientLockedTokens.as_ref()
    );
    ...
}
``` [2](#0-1) 

If `set_locked_tokens` is called with `amount = 0` (or any value below the true pending sum) while transfers are in flight, every subsequent call to `fin_transfer_callback` or `process_fin_transfer_to_other_chain` that tries to unlock those tokens will panic with `ERR_INSUFFICIENT_LOCKED_TOKENS`, permanently blocking finalization.

Conversely, setting the value to an inflated number allows `unlock_tokens` to succeed for amounts that were never legitimately locked, enabling over-release of escrowed assets.

The `TokenLockController` role is defined alongside all other privileged roles in the bridge: [3](#0-2) 

### Impact Explanation

**Freeze path (set to 0 / below real pending sum):** Every pending `TransferMessage` stored in `pending_transfers` that targets the zeroed chain/token pair becomes permanently unresolvable. The relayer's `fin_transfer` call will revert at the `unlock_tokens` check. Users have already sent tokens on the source chain; they cannot receive on the destination chain and cannot recover their funds. This constitutes permanent freezing of bridged funds.

**Over-release path (set to inflated value):** `unlock_tokens` will succeed for amounts exceeding what was ever legitimately locked. Combined with a valid proof submitted by any relayer, this allows the bridge to release or mint tokens beyond the true escrowed supply, breaking the 1:1 backing invariant and enabling theft of other users' deposits.

Both impacts fall squarely within the "Critical — permanent freezing of bridged funds" and "Critical — balance manipulation / escrow mis-accounting" categories.

### Likelihood Explanation

The `TokenLockController` role is a distinct, non-DAO role that can be granted to operational accounts (e.g., migration scripts, automated rebalancers). Any account holding this role — whether compromised, misconfigured, or acting maliciously — can trigger the impact with a single transaction. The function requires no attached deposit, no proof, and no time delay. The attack is silent: no event is emitted by `set_locked_tokens` itself, so the manipulation may go undetected until users attempt to finalize transfers.

### Recommendation

1. **Remove or heavily restrict `set_locked_tokens`**: If the function is needed only for one-time migration, gate it behind `Role::DAO` exclusively and add a migration-complete flag that permanently disables it afterward.
2. **Add a lower-bound invariant**: Before overwriting, assert that the new value is ≥ the sum of all pending transfer amounts for that pair, or at minimum emit a verifiable on-chain event with the old and new values.
3. **Emit an event**: Any change to `locked_tokens` via this administrative path should emit a structured log so off-chain monitors can detect unexpected reductions.
4. **Time-lock significant reductions**: Require a governance delay before a reduction in locked balance takes effect, giving users time to react.

### Proof of Concept

1. User A initiates a transfer of 1000 USDC from Ethereum to NEAR. `lock_tokens` sets `locked_tokens[(Eth, usdc.near)] = 1000`.
2. `TokenLockController` calls `set_locked_tokens([{chain_kind: Eth, token_id: "usdc.near", amount: 0}])`.
3. Relayer submits `fin_transfer` with a valid Ethereum proof for User A's transfer.
4. Inside `fin_transfer_callback`, `unlock_tokens(Eth, usdc.near, 1000)` reads `available = 0`, fails the `require!(available >= amount)` check, and panics with `ERR_INSUFFICIENT_LOCKED_TOKENS`.
5. The transaction reverts. User A's 1000 USDC is burned/locked on Ethereum and can never be released on NEAR. Funds are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/token_lock.rs (L38-44)
```rust
    #[access_control_any(roles(Role::DAO, Role::TokenLockController))]
    pub fn set_locked_tokens(&mut self, args: Vec<SetLockedTokenArgs>) {
        for arg in args {
            self.locked_tokens
                .insert(&(arg.chain_kind, arg.token_id), &arg.amount.0);
        }
    }
```

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L113-129)
```rust
#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    DAO,
    PauseManager,
    UnrestrictedDeposit,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    MetadataManager,
    UnrestrictedRelayer,
    TokenControllerUpdater,
    NativeFeeRestricted,
    RbfOperator,
    TokenUpgrader,
    TokenLockController,
    RelayerManager,
}
```

**File:** near/omni-bridge/src/lib.rs (L241-243)
```rust
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
}
```
