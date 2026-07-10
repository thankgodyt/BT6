### Title
`safe_mint` Silently Locks User Funds When Recipient Account Is Unregistered - (File: contracts/nbtc/src/lib.rs)

### Summary

`safe_mint` in the nBTC token contract mints tokens to the bridge account and then silently returns `U128(0)` when the recipient account is not registered in the token contract. The minted tokens remain in the bridge account with no on-chain record of their rightful owner, permanently locking user funds without any automated recovery path.

### Finding Description

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function executes in two distinct steps:

1. **Unconditional mint to bridge** (line 112): `self.token.internal_deposit(&self.bridge_id, amount.into())` — tokens are credited to `bridge_id` regardless of whether the recipient is registered.
2. **Silent early return** (lines 114–116): if `self.token.accounts.get(&account_id).is_none()`, the function returns `PromiseOrValue::Value(U128(0))` without transferring anything to the user and without recording the stranded amount anywhere. [1](#0-0) 

The contrast with the `mint` function is instructive: `mint` calls `mint_inner`, which auto-registers the account before depositing (lines 342–345), so it never silently drops funds. `safe_mint` has no such guard. [2](#0-1) 

The bridge does have a `lost_found` ledger used in `transfer_nbtc_callback` (lines 62–70 of `token_transfer.rs`) to record failed transfers for later recovery. `safe_mint` does not write to this ledger, so the stranded tokens are invisible to any recovery mechanism. [3](#0-2) 

### Impact Explanation

A user who deposits BTC and whose NEAR account is not yet registered in the nBTC token contract will:
- Have their BTC locked in the bridge's Bitcoin UTXO set (irreversible on-chain).
- Have nBTC minted to the bridge account with no on-chain attribution to them.
- Receive zero nBTC.
- Have no automated path to recover funds; manual operator intervention is required, and the operator has no on-chain record of the debt.

This matches the **Medium** impact class: *broken callback rollback / stuck bridge state requiring operator intervention*, and borders on Critical given the absence of any recovery record.

### Likelihood Explanation

Account registration in NEP-141 is a prerequisite that many users overlook, especially first-time depositors who interact with the bridge before calling `storage_deposit` on the nBTC contract. The entry path is fully unprivileged: any user can trigger this by submitting a valid BTC deposit proof for an unregistered NEAR account. No special role or key is required.

### Recommendation

Replace the silent early-return with one of the following:

1. **Revert** if the recipient account is not registered, so the deposit proof submission fails cleanly and the user can retry after registering. This mirrors the ERC777 `preventLocking` fix: fail loudly rather than silently swallowing funds.
2. **Write to `lost_found`** before returning, so the stranded amount is recorded on-chain and the user (or operator) can later claim it via the existing recovery path.

Option 1 is simpler and safer; option 2 preserves liveness at the cost of added complexity.

### Proof of Concept

1. User Alice has not called `storage_deposit` on the nBTC contract; her account is unregistered.
2. Alice sends 0.01 BTC to her bridge deposit address.
3. A relayer calls `verify_deposit` on the satoshi-bridge, which eventually calls `safe_mint(alice.near, 1_000_000, None)` on the nBTC contract.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — 1 000 000 satoshi-units of nBTC are credited to the bridge account.
5. `self.token.accounts.get(&alice.near)` returns `None`; the function returns `U128(0)`.
6. Alice's nBTC balance is 0. The bridge's nBTC balance is inflated by 1 000 000. No `lost_found` entry exists for Alice. Alice's BTC is permanently locked in the bridge UTXO. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L341-346)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L61-72)
```rust
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
```
