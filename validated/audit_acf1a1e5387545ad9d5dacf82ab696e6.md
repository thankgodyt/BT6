### Title
Unset `withdraw_relayer` Causes `ft_transfer` to Permanently Lock User nBTC in the Token Contract — (File: `contracts/nbtc/src/lib.rs`)

### Summary

The `ft_transfer` override in the `nbtc` contract contains a legacy Near Intents bridging path. When `receiver_id == env::current_account_id()` and the memo starts with `"WITHDRAW_TO:"`, the code attempts to redirect the transfer to a configured `withdraw_relayer`. If `withdraw_relayer` has never been set (it is stored in optional contract storage and defaults to `None`), the redirect silently falls through and the standard `self.token.ft_transfer(receiver_id, amount, memo)` is called with `receiver_id` equal to the nbtc contract itself. Once the nbtc contract's own account is registered in the token (achievable by any caller via the public `storage_deposit`), user tokens are permanently transferred into the nbtc contract's own balance with no recovery path.

### Finding Description

`ft_transfer` in `contracts/nbtc/src/lib.rs` overrides the NEP-141 standard:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // Legacy bridging flow used by Near Intents
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
        // ← NO else-branch: falls through silently when withdraw_relayer is None
    }
    self.token.ft_transfer(receiver_id, amount, memo);  // receiver_id == self
}
``` [1](#0-0) 

`withdraw_relayer` is read from raw contract storage and is `None` until the controller explicitly calls `set_withdraw_relayer_address`. There is no check at initialization or at call time that the relayer is configured before the legacy path is entered. [2](#0-1) [3](#0-2) 

The `new()` constructor only registers `bridge_id` in the token; the nbtc contract's own account is not registered by default. [4](#0-3) 

However, `storage_deposit` is public and permissionless — any caller can register any account, including the nbtc contract itself: [5](#0-4) 

Once the nbtc contract is registered, the fallthrough `self.token.ft_transfer(receiver_id, amount, memo)` executes successfully, depositing the user's tokens into the nbtc contract's own balance. No existing function can recover those tokens: `burn` only withdraws from `self.bridge_id`, not from the nbtc contract's own account. [6](#0-5) 

### Impact Explanation

User nBTC tokens are permanently locked inside the nbtc contract with no recovery mechanism. The total supply remains unchanged (tokens are not burned), but the locked tokens are irrecoverable, breaking the 1:1 BTC backing invariant for affected users. This matches **permanent locking of user funds**.

### Likelihood Explanation

- The `withdraw_relayer` is an optional, post-deployment configuration. Any deployment window where it has not yet been set is vulnerable.
- Registering the nbtc contract via `storage_deposit` costs only the standard NEAR storage fee (~0.00125 NEAR) and is callable by any account.
- Near Intents users are explicitly expected to use the `"WITHDRAW_TO:"` memo pattern (the comment in the code names this flow), making accidental triggering realistic.
- The combination of two low-effort preconditions (unset relayer + one `storage_deposit` call) makes exploitation straightforward.

### Recommendation

Add an explicit guard in `ft_transfer` so that when the WITHDRAW_TO condition is met but `withdraw_relayer` is `None`, the call panics rather than falling through:

```rust
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    let relayer = Self::read_withdraw_relayer_address()
        .unwrap_or_else(|| env::panic_str("withdraw_relayer not configured"));
    return self.token.ft_transfer(relayer, amount, memo);
}
```

This mirrors the fix recommended in the Celo report: validate the identifier before using it, so that misconfiguration causes a safe revert rather than silent misbehavior.

### Proof of Concept

1. Deploy the nbtc contract without calling `set_withdraw_relayer_address` (default state).
2. Any account calls `storage_deposit(Some(nbtc_contract_id), None)` with sufficient NEAR to register the nbtc contract in its own token.
3. A user holding nBTC calls:
   ```
   ft_transfer(
     receiver_id = <nbtc_contract_id>,
     amount      = <user_balance>,
     memo        = Some("WITHDRAW_TO:bc1q...")
   )
   ```
   with 1 yoctoNEAR attached (standard NEP-141 requirement).
4. `withdraw_relayer` is `None` → the `if let Some(...)` branch is skipped → execution falls through to `self.token.ft_transfer(nbtc_contract_id, amount, memo)`.
5. The standard transfer succeeds: tokens are withdrawn from the user and deposited into the nbtc contract's own registered balance.
6. The user's nBTC balance is now zero; the nbtc contract holds the tokens. No `burn`, `ft_transfer`, or admin function exists to recover them from that balance. [1](#0-0) [7](#0-6)

### Citations

**File:** contracts/nbtc/src/lib.rs (L37-38)
```rust
const WITHDRAW_RELAYER_ADDRESS: &[u8] = b"WITHDRAW_RELAYER_ADDRESS";
const WITHDRAW_MEMO_PREFIX: &str = "WITHDRAW_TO:";
```

**File:** contracts/nbtc/src/lib.rs (L86-89)
```rust
        contract
            .token
            .internal_register_account(&contract.bridge_id);

```

**File:** contracts/nbtc/src/lib.rs (L157-159)
```rust
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
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

**File:** contracts/nbtc/src/lib.rs (L239-246)
```rust
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }
```

**File:** contracts/nbtc/src/lib.rs (L324-328)
```rust
    pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
        self.assert_controller();

        env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
    }
```

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
