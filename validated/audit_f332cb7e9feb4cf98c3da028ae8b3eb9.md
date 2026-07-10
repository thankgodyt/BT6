### Title
Missing Caller Authorization in `withdraw_rbf` Allows Any User to Modify Another User's Pending Withdrawal — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`withdraw_rbf` is a public, unprivileged function that accepts an arbitrary `original_btc_pending_verify_id` identifying any user's pending withdrawal. It retrieves the caller via `env::predecessor_account_id()` but **never verifies that the caller is the owner of the referenced pending transaction**. An attacker can call `withdraw_rbf` on a victim's pending withdrawal with attacker-controlled `output`, submitting a replacement transaction that redirects BTC to an attacker-controlled address.

### Finding Description

The vulnerability class is identical to the external report: a function performs an existence/capacity check on the caller but never compares the caller against the actual owner of the resource being acted upon.

In `withdraw_rbf`:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,   // ← identifies ANY user's pending tx
    output: Vec<TxOut>,                        // ← attacker-controlled outputs
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();  // ← caller, not owner
    self.require_pending_sign_capacity(&account_id); // ← checks caller's capacity only

    self.withdraw_rbf_chain_specific(
        account_id,                            // ← caller passed as "owner"
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
``` [1](#0-0) 

The function never fetches `btc_pending_info.account_id` for `original_btc_pending_verify_id` and never asserts `env::predecessor_account_id() == btc_pending_info.account_id`.

Compare this to the privileged `cancel_withdraw`, which correctly retrieves the owner from the pending info before acting:

```rust
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
``` [2](#0-1) 

`cancel_withdraw` is restricted to `Role::DAO` / `Role::Operator` and correctly derives the account from the pending info. `withdraw_rbf` is unrestricted and uses the caller's identity instead — the missing ownership check is the root cause.

Each `BTCPendingInfo` stores the legitimate owner in its `account_id` field: [3](#0-2) 

### Impact Explanation

An attacker calls `withdraw_rbf(victim_pending_id, attacker_outputs, ...)` where `attacker_outputs` contains a BTC address controlled by the attacker. The bridge constructs a replacement (RBF) transaction spending the same UTXOs as the victim's original withdrawal but paying to the attacker's address. This replacement is submitted to the MPC signing pipeline. If signed and broadcast, the victim's BTC is redirected to the attacker. This is a **direct theft of user funds** matching the Critical impact tier: "Significant loss, theft, destruction, or permanent locking of user or protocol funds."

### Likelihood Explanation

`withdraw_rbf` is a public function with no `#[access_control_any]` guard and no `assert_one_yocto()` requirement. Any NEAR account can call it at any time against any pending withdrawal. The only prerequisite is knowing a victim's `btc_pending_verify_id`, which is emitted as an on-chain event (`GenerateBtcPendingInfo`) and queryable via view methods. Likelihood is **high**.

### Recommendation

Add an ownership assertion at the start of `withdraw_rbf`, mirroring the pattern used in `cancel_withdraw`:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let caller = env::predecessor_account_id();
    // Verify caller owns the pending transaction
    let owner = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    require!(caller == owner, "Only the withdrawal owner can call withdraw_rbf");

    self.require_pending_sign_capacity(&caller);
    self.withdraw_rbf_chain_specific(
        caller,
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
```

### Proof of Concept

1. Alice calls `ft_transfer_call` to initiate a withdrawal; the bridge emits `GenerateBtcPendingInfo { account_id: alice, btc_pending_id: "abc123" }`.
2. Attacker Bob observes the event and calls:
   ```
   withdraw_rbf(
     original_btc_pending_verify_id: "abc123",
     output: [TxOut { value: alice_amount - fee, script_pubkey: bob_address }],
     chain_specific_data: None
   )
   ```
3. Because there is no ownership check, the call succeeds. `withdraw_rbf_chain_specific` is invoked with Bob as `account_id` and Alice's UTXO as input, constructing a replacement transaction paying Bob.
4. The MPC pipeline signs the replacement. Once broadcast, Alice's BTC is sent to Bob.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L287-291)
```rust
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
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
