### Title
Premature Token Minting in `safe_mint` Permanently Locks User Funds When Recipient Account Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

In the nBTC token contract's `safe_mint` function, tokens are minted to `bridge_id` **before** checking whether the recipient account is registered. If the recipient is not registered, the function returns early with `U128(0)`, leaving the minted tokens permanently stuck in `bridge_id` with no automatic recovery path for the user.

---

### Finding Description

The `safe_mint` function performs state mutation (minting) before the guard check (registration), mirroring the exact structural flaw in the reported `VotingDelegationLib` bug: state is irrevocably changed before a condition is evaluated that depends on that state, causing incorrect downstream behavior.

```rust
// contracts/nbtc/src/lib.rs lines 101-124
pub fn safe_mint(
    &mut self,
    account_id: AccountId,
    amount: U128,
    msg: Option<String>,
) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(
        account_id != self.bridge_id,
        "safe_mint: account_id must not be the bridge"
    );
    // ① Tokens are minted to bridge_id unconditionally
    self.token.internal_deposit(&self.bridge_id, amount.into());

    // ② Only NOW is the recipient's registration checked
    if self.token.accounts.get(&account_id).is_none() {
        // ③ Returns early — minted tokens are now stuck in bridge_id
        return PromiseOrValue::Value(U128(0));
    }
    // ④ Transfer only reached if account was already registered
    ...
}
``` [1](#0-0) 

Step ① mints `amount` nBTC into `bridge_id`'s balance, permanently increasing total supply. Step ② then checks whether `account_id` is a registered NEP-141 account. If it is not (step ③), the function returns `U128(0)` without transferring the newly minted tokens. The tokens now exist in `bridge_id`'s balance with no on-chain mechanism to route them to the user or burn them back.

The `burn` function only withdraws from `bridge_id` and is callable only by the bridge contract itself: [2](#0-1) 

There is no view or callback path that automatically detects the stuck balance and re-routes it. The bridge contract receives `U128(0)` from `safe_mint` but the deposit UTXO has already been marked verified in `verified_deposit_utxo`, blocking any future `verify_deposit` retry for the same UTXO.

---

### Impact Explanation

A user who deposits BTC to the bridge address but whose NEAR account is not yet registered in the nBTC contract (a standard NEP-141 storage-registration requirement) will:

1. Have their BTC permanently locked in the bridge's Bitcoin address (the deposit is verified and the UTXO consumed).
2. Receive zero nBTC — the minted tokens sit in `bridge_id` with no automatic delivery.
3. Have no on-chain recourse: the UTXO is marked verified, preventing re-submission; no refund path exists for a successfully verified deposit.

This constitutes **permanent locking of user funds** and **supply inflation** (total nBTC supply increases without a corresponding user balance), matching the allowed critical/medium impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds"* and *"broken callback rollback, or stuck bridge state requiring operator intervention."*

---

### Likelihood Explanation

NEP-141 storage registration is a separate, explicit transaction that many users omit, especially when interacting via relayers or cross-chain tooling that does not enforce pre-registration. Any deposit where the recipient NEAR account has never called `storage_deposit` on the nBTC contract triggers this path. This is a realistic, unprivileged, user-controlled condition requiring no special access.

---

### Recommendation

Move the registration check **before** the `internal_deposit` call, so tokens are only minted once delivery is confirmed possible:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration FIRST
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    // Only mint after confirming recipient can receive
    self.token.internal_deposit(&self.bridge_id, amount.into());
    ...
}
```

Alternatively, auto-register the account before minting (paying storage from attached deposit), or return an error to the bridge contract that triggers a refund flow rather than silently succeeding.

---

### Proof of Concept

1. User sends BTC to the bridge-derived deposit address.
2. Relayer calls `verify_deposit` on the bridge contract; proof is valid.
3. Bridge contract calls `safe_mint(user.near, 100000, None)` on the nBTC contract.
4. `user.near` has never called `storage_deposit` on nBTC — account is unregistered.
5. `internal_deposit(&bridge_id, 100000)` executes — 100,000 satoshis of nBTC are minted into `bridge_id`'s balance; total supply increases by 100,000.
6. `accounts.get(&user.near).is_none()` → `true` → function returns `U128(0)`.
7. Bridge contract receives `U128(0)`, deposit UTXO is recorded in `verified_deposit_utxo`.
8. **Result**: User's BTC is locked in the bridge forever; user holds 0 nBTC; 100,000 nBTC are stranded in `bridge_id` with no automated recovery. [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
```
