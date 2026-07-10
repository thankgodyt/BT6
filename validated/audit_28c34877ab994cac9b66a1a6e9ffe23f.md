### Title
Tokens Minted to Bridge Account But Not Transferred to Unregistered User in `safe_mint`, Causing Permanent Fund Loss - (File: contracts/nbtc/src/lib.rs)

### Summary
In `safe_mint`, nBTC tokens are unconditionally minted to the bridge's own account before checking whether the recipient has registered for storage. If the recipient is unregistered, the function returns early with `U128(0)`, leaving the minted tokens permanently stuck in the bridge account. The user's BTC deposit is consumed but they receive zero nBTC.

### Finding Description
The `safe_mint` function in `contracts/nbtc/src/lib.rs` follows this sequence:

1. Calls `self.token.internal_deposit(&self.bridge_id, amount.into())` — unconditionally minting `amount` nBTC into the bridge's own token balance, increasing total supply.
2. Checks `if self.token.accounts.get(&account_id).is_none()` — if the recipient has no registered storage account, returns `PromiseOrValue::Value(U128(0))` immediately.
3. Only if the account IS registered does it proceed to `ft_transfer` or `ft_transfer_call` to move tokens from bridge to user. [1](#0-0) 

When the early return fires (step 2), the `amount` tokens remain credited to `bridge_id` inside the nbtc `FungibleToken` ledger. The satoshi-bridge contract receives the return value `0` and has no mechanism to detect or recover the orphaned balance. There is no `lost_found` entry created in the bridge for this case, and no refund path back to the depositor. [2](#0-1) 

The `lost_found` map in the satoshi-bridge is only populated by `transfer_nbtc_callback` when an explicit `ft_transfer` cross-contract call fails — a code path that is never reached here because the early return happens before any transfer is attempted. [3](#0-2) 

### Impact Explanation
**Critical — Permanent loss of user funds.**

The user's native BTC UTXO is consumed and recorded as a verified deposit. The nBTC supply increases by `amount` (tokens exist in the bridge's own balance), but the user's NEAR account balance remains zero. There is no recovery path: the satoshi-bridge does not track the orphaned nBTC, and the nbtc contract has no admin function to redistribute tokens stuck in `bridge_id`. The user permanently loses their deposited BTC with no recourse.

### Likelihood Explanation
**Medium-High.** NEAR storage registration is a prerequisite that many users overlook. A user who sends BTC to their deposit address without first calling `storage_deposit` on the nbtc contract will trigger this path. The deposit flow is permissionless and relayer-driven — the relayer submits the proof regardless of whether the recipient is registered, making this a realistic scenario for any new or inattentive user.

### Recommendation
Move the storage-registration check **before** minting. If the account is unregistered, either:
- Register the account automatically (using attached deposit or a pre-funded reserve), then proceed with the transfer, or
- Abort the entire `safe_mint` call without minting, and record the amount in `lost_found` so the user can recover after registering.

The invariant must be: tokens are only minted if and only if they will be credited to the intended recipient.

### Proof of Concept
1. Alice sends 0.01 BTC to her bridge deposit address on Bitcoin.
2. Alice has never called `storage_deposit` on the nbtc contract, so `token.accounts.get(&alice)` returns `None`.
3. A relayer submits the `TxInclusionProof` to the satoshi-bridge's `verify_deposit`.
4. The bridge calls `nbtc.safe_mint(alice, 1_000_000, None)`.
5. Inside `safe_mint`: `internal_deposit(&bridge_id, 1_000_000)` executes — total nBTC supply increases by 1,000,000 satoshis, all credited to `bridge_id`.
6. `token.accounts.get(&alice)` is `None` → function returns `U128(0)`.
7. The satoshi-bridge receives `0`, logs nothing, creates no `lost_found` entry.
8. Alice's NEAR balance: 0 nBTC. Bridge's nBTC balance: +1,000,000 (unreachable by Alice). Alice's BTC: gone. [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-67)
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
```
