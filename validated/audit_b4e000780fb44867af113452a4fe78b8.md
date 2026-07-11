### Title
`safe_mint` Inflates nBTC Total Supply Without Burning Orphaned Tokens When Recipient Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints `amount` tokens into `bridge_id` via `internal_deposit`, then silently returns `U128(0)` without burning those tokens when the recipient account is not registered. This is the NEAR analog of an unchecked ERC-20 `transfer` result: the mint side-effect executes and persists, but the delivery to the user silently fails, permanently inflating the nBTC total supply above the BTC-backed amount.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` (lines 101–124):

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← tokens minted here

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← returns WITHOUT burning
    }
    ...
}
``` [1](#0-0) 

The execution path when `account_id` is unregistered:

1. **Line 112**: `internal_deposit(&self.bridge_id, amount)` — increases `bridge_id`'s balance and the global total supply by `amount`. This is a permanent, committed state change.
2. **Lines 114–116**: The unregistered-account guard fires and returns `U128(0)` immediately — **without calling `internal_withdraw` or any burn on `bridge_id`**.

The minted tokens are now orphaned inside `bridge_id`. No subsequent code path in `safe_mint` cleans them up.

The `mint_inner` helper (lines 341–352) confirms that `internal_deposit` is the sole supply-creation mechanism and emits an `FtMint` event, so the inflation is observable on-chain: [2](#0-1) 

---

### Impact Explanation

- **Supply/backing invariant broken**: nBTC total supply exceeds the amount of BTC actually received by users. Every unregistered-account `safe_mint` call permanently widens this gap.
- **User funds effectively lost**: The depositing user's BTC is locked in the bridge's on-chain deposit address. The UTXO is marked verified by the bridge (preventing re-deposit), yet the user receives 0 nBTC.
- **Tokens stuck in `bridge_id`**: The orphaned tokens accumulate in `bridge_id` with no automatic recovery path. A privileged operator would need to manually burn them to restore the invariant.

This matches the **Medium** allowed impact: *"Harmful smart-contract behavior without direct funds theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention."* It also borders **Critical** ("Unauthorized minting … of nBTC") because nBTC is minted and credited to `bridge_id` without any corresponding BTC being released to a user.

---

### Likelihood Explanation

`safe_mint` is the code path taken by `verify_deposit_v2` when `deposit_msg.safe_deposit` is `Some(..)` (the Omni Bridge / safe-deposit flow). A user who deposits BTC before their NEAR account is storage-registered — a realistic ordering, since BTC confirmations take time — will trigger this path. No special privilege is required; any public bridge user can reach it. [3](#0-2) 

---

### Recommendation

Burn the orphaned tokens from `bridge_id` before returning `U128(0)`:

```rust
if self.token.accounts.get(&account_id).is_none() {
    // Undo the deposit so total supply stays backed 1:1
    self.token.internal_withdraw(&self.bridge_id, amount.into());
    return PromiseOrValue::Value(U128(0));
}
```

Alternatively, register the account on-the-fly (as `mint_inner` already does) so the transfer can proceed rather than aborting after the mint.

---

### Proof of Concept

1. User deposits BTC; the bridge's deposit callback calls `safe_mint(unregistered.near, 100_000_000, None)` on the nBTC contract.
2. `internal_deposit(&bridge_id, 100_000_000)` executes — total supply increases by `100_000_000`, `bridge_id` balance increases by `100_000_000`.
3. `self.token.accounts.get(&unregistered.near).is_none()` → `true`.
4. Function returns `U128(0)` — **no burn, no rollback**.
5. The bridge's callback receives `U128(0)`, marks the UTXO as verified (blocking re-deposit), and the user receives 0 nBTC.
6. `ft_total_supply()` now reports 100,000,000 satoshis more nBTC than are redeemable, permanently. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L341-352)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: account_id,
            amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-102)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
    ) -> Promise {
        let coinbase_proof = Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof));
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
    }
```
