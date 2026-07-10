### Title
Unauthorized `withdraw_rbf` Allows Any Caller to Submit RBF on Another User's Pending Withdrawal — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`withdraw_rbf` is a publicly callable function that accepts an arbitrary `original_btc_pending_verify_id` and attacker-controlled `output: Vec<TxOut>`, but never verifies that `env::predecessor_account_id()` is the owner of that pending withdrawal. Any unprivileged NEAR account can invoke it against any victim's pending withdrawal, creating a competing RBF transaction and interfering with the victim's bridge state.

### Finding Description
`withdraw_rbf` is documented as the mechanism by which *the user* accelerates their own pending withdrawal by increasing the gas fee. However, the function contains no ownership check:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();   // ← caller, not original owner
    self.require_pending_sign_capacity(&account_id);  // ← checks caller's quota, not victim's

    self.withdraw_rbf_chain_specific(
        account_id,                          // ← attacker's account becomes the RBF owner
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
``` [1](#0-0) 

The contrast with `cancel_withdraw` — which is restricted to `DAO/Operator` and explicitly fetches the original owner from the pending info — makes the omission clear:

```rust
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
self.require_pending_sign_capacity(&user_account_id);
``` [2](#0-1) 

`BTCPendingInfo` stores the legitimate owner in `account_id`: [3](#0-2) 

Because `withdraw_rbf` passes the *caller's* `account_id` to `withdraw_rbf_chain_specific`, the newly created RBF `BTCPendingInfo` is registered under the attacker's account, not the victim's. The victim's original pending transaction now has a competing RBF it did not authorize.

### Impact Explanation
**Medium — attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention.**

- An attacker can submit an unsolicited RBF against any victim's pending withdrawal. The victim's original `BTCPendingInfo` is now racing against an attacker-owned RBF entry.
- The victim cannot easily cancel or supersede the attacker's RBF because `cancel_withdraw` is restricted to `DAO/Operator`.
- The attacker controls the `output: Vec<TxOut>` supplied to the RBF. If `withdraw_rbf_chain_specific` does not re-validate that the recipient address matches the original withdrawal target, this escalates to a Critical impact (fund redirection to an attacker-controlled Bitcoin address).
- Even without fund redirection, the victim's withdrawal is stuck until an operator intervenes, satisfying the "stuck bridge state requiring operator intervention" medium impact criterion.

### Likelihood Explanation
**High.** `withdraw_rbf` carries only a `#[pause]` guard (bypassable by `DAO`) and no role restriction. Any NEAR account can call it with any `original_btc_pending_verify_id` obtained from on-chain events or view calls. No special privilege, leaked key, or social engineering is required.

### Recommendation
Mirror the pattern used in `cancel_withdraw`: fetch the original owner from the pending info and assert that the caller matches before proceeding.

```diff
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
-   let account_id = env::predecessor_account_id();
-   self.require_pending_sign_capacity(&account_id);
+   let caller = env::predecessor_account_id();
+   let account_id = self
+       .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
+       .account_id
+       .clone();
+   require!(
+       caller == account_id,
+       "Only the withdrawal owner can submit an RBF"
+   );
+   self.require_pending_sign_capacity(&account_id);

    self.withdraw_rbf_chain_specific(
        account_id,
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
```

### Proof of Concept
1. Alice calls `ft_transfer_call` → `ft_on_transfer` → a `BTCPendingInfo` is created with `account_id = alice.near` and `btc_pending_id = "abc123"`. The entry moves to `PendingVerify` stage after signing.
2. Attacker (Bob) observes the emitted `GenerateBtcPendingInfo` event and learns `btc_pending_id = "abc123"`.
3. Bob calls `withdraw_rbf("abc123", [TxOut { value: ..., script_pubkey: bob_btc_address }], None)`.
4. Inside `withdraw_rbf`, `account_id = bob.near`. `require_pending_sign_capacity` checks Bob's quota (passes if Bob has capacity). `withdraw_rbf_chain_specific(bob.near, "abc123", ...)` is called.
5. A new `BTCPendingInfo` is created owned by Bob, referencing Alice's original transaction as the RBF target. Alice's withdrawal is now competing with Bob's unauthorized RBF, leaving her funds stuck in the bridge until operator intervention. [1](#0-0) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-299)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L107-127)
```rust
pub struct BTCPendingInfo {
    pub account_id: AccountId,
    pub btc_pending_id: String,
    #[serde(with = "u128_dec_format")]
    pub transfer_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub actual_received_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub withdraw_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub gas_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub burn_amount: u128,
    pub psbt_hex: String,
    pub vutxos: Vec<VUTXO>,
    pub signatures: Vec<Option<SignatureResponse>>,
    pub tx_bytes_with_sign: Option<Vec<u8>>,
    pub create_time_sec: u32,
    pub last_sign_time_sec: u32,
    pub state: PendingInfoState,
}
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```
