### Title
`safe_mint` Mints nBTC to Bridge Account Before Recipient Registration Check, Causing Unbacked Supply Inflation - (File: contracts/nbtc/src/lib.rs)

### Summary
The `safe_mint` function in the nbtc contract mints tokens to the bridge's own nbtc balance **before** checking whether the intended recipient has registered storage. When the recipient is unregistered, the function returns `U128(0)` without transferring the already-minted tokens, leaving them permanently stuck in the bridge's nbtc balance. Because NEAR cross-contract state changes are not atomic across contracts, the bridge's callback cannot roll back the nbtc minting even when it reverts its own deposit state. This permanently inflates the nbtc total supply beyond the actual BTC backing.

### Finding Description
In `contracts/nbtc/src/lib.rs`, the `safe_mint` function executes in this order:

1. **Mints tokens to the bridge's own account** (line 112): `self.token.internal_deposit(&self.bridge_id, amount.into())`
2. **Then** checks if the recipient is registered (line 114): `if self.token.accounts.get(&account_id).is_none()`
3. If unregistered, **returns `U128(0)` immediately** (line 115) — without transferring the already-minted tokens [1](#0-0) 

The `internal_deposit` call at line 112 is an irreversible state mutation that increases the bridge's nbtc balance. The registration check at line 114 comes too late. When the recipient is unregistered, the function exits at line 115 and the minted tokens remain in the bridge's nbtc balance with no recovery path.

The safe deposit flow (entered via `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(...)`) is documented to "revert the whole transaction if minting fails." [2](#0-1) 

However, in NEAR's async execution model, cross-contract state changes are committed per-contract. When the bridge's callback receives `U128(0)` and reverts its own deposit state (un-marking the UTXO as verified), the nbtc contract's state — including the minted tokens — is already committed on-chain and cannot be rolled back by the bridge's callback. The `burn` function in nbtc is only callable by the bridge and is only invoked after verified on-chain withdrawals, so there is no normal operational path to remove these stuck tokens. [3](#0-2) 

### Impact Explanation
Each triggering event permanently mints `amount` nBTC tokens to the bridge's nbtc balance without any BTC backing. This breaks the 1:1 BTC-to-nBTC backing invariant: the nbtc total supply grows above the actual BTC held by the bridge. The unbacked tokens accumulate in the bridge's nbtc balance indefinitely. They cannot be legitimately burned (burn is only called after verified withdrawals) and cannot be transferred to users through normal deposit flows. This constitutes a broken callback rollback and stuck bridge state requiring operator intervention, matching the Medium impact class.

### Likelihood Explanation
The `safe_deposit` path is a publicly documented and actively used integration path (e.g., Omni Bridge). Any unprivileged user can submit a `verify_deposit_v2` call with `deposit_msg.safe_deposit = Some(...)` and `deposit_msg.recipient_id` set to any NEAR account that has not called `storage_deposit` on the nbtc contract — for example, a freshly created account, a contract account, or any account the user controls that has not registered. No privileged role is required. The user only needs to have made a real BTC deposit to the derived address. [4](#0-3) 

### Recommendation
Move the recipient registration check **before** the `internal_deposit` call. If the recipient is not registered, return early without minting any tokens:

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
    // Check registration BEFORE minting — prevents unbacked token inflation
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }
    self.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L56-58)
```rust
    ///   the user's token storage (see `required_balance_for_safe_deposit`).
    /// * `None` — standard deposit: charges the deposit fee, pays the user's storage, and
    ///   routes mint failures to lost & found.
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
