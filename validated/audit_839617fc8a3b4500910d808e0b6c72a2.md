### Title
DAO Role Can Unilaterally Drain Bridge Escrow Without Updating Locked-Token Accounting — (`File: near/omni-bridge/src/lib.rs`)

### Summary
`transfer_token_as_dao` allows any account holding `Role::DAO` to transfer an arbitrary amount of any token held by the bridge contract to any recipient, with no checks against the `locked_tokens` escrow accounting. This is the direct analog of the external report's "folio owner rug pull": a privileged role can silently drain user funds that are in-flight across chains without making any code change.

### Finding Description
The bridge contract exposes `transfer_token_as_dao`, gated solely by `#[access_control_any(roles(Role::DAO))]`:

```rust
#[access_control_any(roles(Role::DAO))]
pub fn transfer_token_as_dao(
    &mut self,
    token: AccountId,
    amount: U128,
    recipient: AccountId,
    msg: Option<String>,
) -> Promise {
    ...
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)
    ...
}
``` [1](#0-0) 

The bridge escrow holds real user tokens during outbound transfers. When a user calls `ft_on_transfer` → `init_transfer`, their tokens are deposited into the bridge contract and the `locked_tokens` map is incremented to track the obligation: [2](#0-1) 

`transfer_token_as_dao` performs a raw `ft_transfer` on the token contract with no reference to `locked_tokens`, no cap on the amount, and no restriction on the recipient. A companion function `set_locked_tokens` (also DAO/`TokenLockController`-gated) can then be used to zero out the accounting: [3](#0-2) 

Together these two calls let a DAO account silently remove all escrowed tokens and erase the on-chain record of the obligation, leaving pending transfers permanently unfinalizable.

### Impact Explanation
Every outbound transfer from NEAR locks real tokens in the bridge contract. A malicious DAO account can call `transfer_token_as_dao(token_id, full_balance, attacker, None)` to move all of those tokens to an attacker-controlled address. Users whose transfers are in the `pending_transfers` map will never receive their funds on the destination chain, and the bridge will have no tokens to release on any subsequent inbound finalization for the same asset. This is a direct theft of bridged funds — matching the "Critical: Stealing, loss, or permanent freezing of bridged funds" impact category. [1](#0-0) 

### Likelihood Explanation
The `Role::DAO` is granted at construction time to `env::predecessor_account_id()` and can subsequently be granted to additional accounts via `acl_grant_role`. There is no time-lock, multi-sig requirement, or on-chain governance delay enforced in the contract itself before `transfer_token_as_dao` executes. Any single account that holds `Role::DAO` can execute the drain in one transaction. The attack requires no code change, no proof, and no relayer cooperation — exactly the threat model described in the external report. [4](#0-3) 

### Recommendation
- **Short term:** Document explicitly that `Role::DAO` must be held by a time-locked, multi-sig, or on-chain governance account, and that `transfer_token_as_dao` is an emergency-only escape hatch. Add a `require` that the requested `amount` does not exceed `total_balance - locked_tokens_sum` for the given token, so the function cannot touch funds that are owed to in-flight transfers.
- **Long term:** Enforce a time-lock or governance delay on `transfer_token_as_dao` at the contract level. Alternatively, restrict the function to only transfer tokens that are demonstrably surplus (i.e., not tracked in `locked_tokens`), and document the full threat model for the DAO role.

### Proof of Concept
1. Alice calls `ft_transfer_call` on a NEP-141 token, sending 1 000 000 tokens to the bridge with an `InitTransfer` message targeting Ethereum. The bridge records the transfer in `pending_transfers` and increments `locked_tokens[(Eth, token_id)]` by 1 000 000.
2. Mallory, who holds `Role::DAO`, calls:
   ```
   transfer_token_as_dao(token_id, 1_000_000, mallory.near, None)
   ```
   The bridge issues `ft_transfer(mallory.near, 1_000_000)` on the token contract. No check against `locked_tokens` is performed.
3. Mallory optionally calls `set_locked_tokens([{chain_kind: Eth, token_id, amount: 0}])` to zero the accounting.
4. Alice's transfer can never be finalized on NEAR (no tokens remain to release), and the MPC signature that was already issued for the Ethereum side is now backed by nothing. Alice's 1 000 000 tokens are permanently lost. [1](#0-0) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L311-313)
```rust
        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), near_sdk::env::predecessor_account_id());
        contract
```

**File:** near/omni-bridge/src/lib.rs (L1511-1530)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
    }
```

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

**File:** near/omni-bridge/src/token_lock.rs (L47-68)
```rust
impl Contract {
    fn lock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        let new_amount = current_amount
            .checked_add(amount)
            .near_expect(TokenLockError::LockedTokensOverflow);

        self.locked_tokens.insert(&key, &new_amount);

        LockAction::Locked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
```
