### Title
`safe_mint` Mints Tokens to Bridge Before Confirming Transfer Succeeds, Leaving Tokens Permanently Locked on Unregistered Recipient - (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens into the bridge's own token balance (`bridge_id`) before verifying that the intended recipient account is registered. When the recipient is not registered, the function silently returns `U128(0)` without burning the already-minted tokens. Because the nBTC contract has no internal recovery path for this case, the minted tokens accumulate in the bridge's nBTC balance with no on-chain mechanism to reclaim them from within the token contract itself.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes the following sequence:

1. **Unconditionally mints** `amount` tokens into `bridge_id`'s balance via `internal_deposit`.
2. **Checks** whether `account_id` is registered in the token contract.
3. If the account is **not registered**, returns `PromiseOrValue::Value(U128(0))` — a silent failure — without burning the tokens that were just minted to `bridge_id`. [1](#0-0) 

The critical sequence is:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into()); // tokens minted here

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0)); // returns without burning
}
``` [2](#0-1) 

The nBTC contract exposes a `burn` function that withdraws from `bridge_id`, but it is only callable by the bridge contract (`assert_bridge()`), and the nBTC contract itself performs no burn in the failure path of `safe_mint`. [3](#0-2) 

The bridge's `verify_deposit_v2` documentation states that the safe deposit path "reverts the whole transaction if minting fails." However, in NEAR Protocol, cross-contract state changes are **not automatically rolled back** when a callback receives a failure signal — the nBTC contract's `internal_deposit` to `bridge_id` is already committed. The bridge's callback would need to explicitly call `burn` on the nBTC contract to undo the mint. [4](#0-3) 

The safe deposit entry path is triggered via `internal_safe_verify_deposit_entry` when `deposit_msg.safe_deposit` is `Some(..)`. [5](#0-4) 

---

### Impact Explanation

Every failed `safe_mint` call (due to an unregistered recipient) mints real nBTC tokens into the bridge's own token balance that are not tracked by the bridge's internal accounting (`acc_collected_protocol_fee`, `cur_available_protocol_fee`, `lost_found`, etc.). [6](#0-5) 

These orphaned tokens inflate the bridge's nBTC balance beyond what is backed by verified BTC deposits, breaking the 1:1 backing invariant. They cannot be recovered through any user-facing function in the nBTC contract. The `lost_found` mechanism in the bridge only covers tokens explicitly routed there by bridge logic — not tokens stranded in the bridge's nBTC balance due to a failed `safe_mint`. [7](#0-6) 

This maps to: **Medium — broken callback rollback / stuck bridge state requiring operator intervention**, and potentially **permanent supply inflation below backed supply** if the bridge callback does not explicitly burn the orphaned tokens.

---

### Likelihood Explanation

The safe deposit flow (`safe_deposit = Some(..)`) is the path used by integrations such as Omni Bridge. Any deposit where the recipient NEAR account has not pre-registered storage in the nBTC token contract triggers the unregistered-account branch of `safe_mint`. This is a realistic scenario: a user bridging BTC for the first time, or a contract account that has never interacted with the nBTC token, will not have a registered storage slot. No special privileges are required — any bridge user submitting a safe deposit proof can trigger this path. [8](#0-7) 

---

### Recommendation

Restructure `safe_mint` to avoid minting tokens before confirming the transfer can succeed:

1. **Check registration before minting**: Move the `accounts.get(&account_id).is_none()` check to before `internal_deposit`. If the account is not registered, revert immediately without minting.
2. **Alternatively, burn on failure**: If the mint-first design is intentional, add an explicit `internal_withdraw` from `bridge_id` in the unregistered-account branch before returning `U128(0)`, so the token supply is restored atomically within the same call.
3. **Add a bridge-side burn in the callback**: Ensure the bridge's safe-deposit callback explicitly calls `burn` on the nBTC contract whenever `safe_mint` returns `U128(0)`, to handle any residual minted balance.

---

### Proof of Concept

1. User sends BTC to a deposit address derived from a NEAR account (`victim.near`) that has **never registered storage** in the nBTC token contract.
2. A relayer (or the user) calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)` and a valid SPV proof.
3. The bridge validates the proof and calls `safe_mint(victim.near, amount, msg)` on the nBTC contract.
4. Inside `safe_mint`:
   - `internal_deposit(&bridge_id, amount)` executes — `amount` nBTC tokens are minted into the bridge's own nBTC balance. **This state change is committed.**
   - `accounts.get(&victim.near)` returns `None` (unregistered).
   - The function returns `PromiseOrValue::Value(U128(0))`.
5. The bridge's callback receives `U128(0)`. If the callback does not explicitly call `burn(bridge_id, amount, ...)` on the nBTC contract, the `amount` tokens remain permanently in the bridge's nBTC balance.
6. The UTXO is not marked as verified (bridge state is correctly reverted), but the nBTC supply is inflated by `amount` with no corresponding BTC backing for those tokens. [1](#0-0) [9](#0-8)

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

**File:** contracts/nbtc/src/lib.rs (L150-159)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L50-102)
```rust
    /// and mint nBTC to the user's NEAR account. Includes coinbase proof for stronger
    /// transaction inclusion verification.
    ///
    /// The deposit flow is selected by `deposit_msg.safe_deposit`:
    /// * `Some(..)` — safe deposit (e.g. Omni Bridge): charges no fee, reverts the whole
    ///   transaction if minting fails (no lost & found), and the caller must attach NEAR for
    ///   the user's token storage (see `required_balance_for_safe_deposit`).
    /// * `None` — standard deposit: charges the deposit fee, pays the user's storage, and
    ///   routes mint failures to lost & found.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - Information used to generate the deposit address path.
    /// * `tx_bytes` - Successfully confirmed BTC transaction bytes.
    /// * `vout` - The index of the output where the user sent BTC to the deposit address.
    /// * `proof` - Transaction inclusion proof with coinbase verification.
    ///
    /// # Returns
    ///
    /// bool - Whether nBTC minting was successful.
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

**File:** contracts/satoshi-bridge/src/lib.rs (L141-146)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
```
