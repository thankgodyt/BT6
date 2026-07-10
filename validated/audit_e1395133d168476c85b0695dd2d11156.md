### Title
Missing Ownership Verification in `withdraw_rbf` Allows Attacker to RBF Another User's Pending Withdrawal - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The public `withdraw_rbf` function accepts an arbitrary `original_btc_pending_verify_id` from the caller without verifying that the pending withdrawal belongs to the caller. An unprivileged attacker can supply a victim's pending-withdrawal ID together with attacker-controlled `output` (BTC destination addresses), potentially redirecting the victim's in-flight BTC withdrawal to the attacker's own Bitcoin address.

### Finding Description
`withdraw_rbf` is an unrestricted public entry point. It captures the caller as `account_id` and immediately passes that caller-controlled identity — together with the user-supplied `original_btc_pending_verify_id` — into `withdraw_rbf_chain_specific`:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 258-274
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,   // ← attacker supplies victim's ID
    output: Vec<TxOut>,                        // ← attacker controls BTC outputs
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();   // attacker
    self.require_pending_sign_capacity(&account_id);  // checks attacker's quota, not victim's

    self.withdraw_rbf_chain_specific(
        account_id,                            // attacker becomes "owner" of new RBF
        original_btc_pending_verify_id,        // victim's pending info
        output,
        chain_specific_data,
    );
}
```

At no point does the function read `btc_pending_info.account_id` and compare it to `env::predecessor_account_id()`. The `require_pending_sign_capacity` guard is applied to the **attacker's** account, not the victim's, which is consistent with the new RBF `BTCPendingInfo` being registered under the attacker's account.

Contrast this with the privileged `cancel_withdraw` function, which correctly derives the owner from the stored pending info before proceeding:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 285-299
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id          // ← reads the real owner from storage
        .clone();
    self.require_pending_sign_capacity(&user_account_id);
    ...
}
```

`cancel_withdraw` is DAO/Operator-only, so it does not need a caller-ownership check, but the pattern shows the codebase knows how to read the real owner. `withdraw_rbf` — which is open to any NEAR account — never performs this lookup.

### Impact Explanation
`withdraw_rbf_chain_specific` receives the attacker's `account_id` as the new RBF owner and the attacker-supplied `output` as the replacement transaction outputs. If the implementation does not internally assert that the stored `BTCPendingInfo.account_id` equals the passed `account_id`, the attacker can:

1. Construct a replacement PSBT that pays the victim's BTC to an attacker-controlled Bitcoin address.
2. Have the MPC network sign the replacement transaction (the bridge cannot distinguish legitimate RBF from attacker-initiated RBF at the signing layer).
3. Broadcast the signed replacement, permanently redirecting the victim's BTC.

This constitutes a **critical** loss of user funds: the victim's nBTC was already burned (or is pending burn) and the underlying BTC is redirected to the attacker.

### Likelihood Explanation
The function is public, requires no attached deposit, no role, and no yoctoNEAR. Any NEAR account can call it at any time against any pending withdrawal that is in the `PendingVerify` stage. The only prerequisite is knowing the victim's `btc_pending_id` (a hex-encoded SHA-256 hash that is emitted as a public on-chain event via `Event::GenerateBtcPendingInfo`). Likelihood is **high**.

### Recommendation
At the top of `withdraw_rbf`, read the stored `BTCPendingInfo` and assert that its `account_id` matches the caller, mirroring the pattern already used elsewhere in the codebase:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();

    // Verify the caller owns this pending withdrawal
    let pending_info = self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
    require!(
        pending_info.account_id == account_id,
        "withdraw_rbf: caller does not own this pending withdrawal"
    );

    self.require_pending_sign_capacity(&account_id);
    self.withdraw_rbf_chain_specific(
        account_id,
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
```

### Proof of Concept
1. Alice calls `ft_transfer_call` to initiate a BTC withdrawal. The bridge emits `Event::GenerateBtcPendingInfo` with `btc_pending_id = "abc123..."`. Alice's pending info enters `PendingVerify` stage.
2. Bob (attacker) observes the event and notes `btc_pending_id = "abc123..."`.
3. Bob calls `withdraw_rbf("abc123...", [TxOut { value: alice_amount, script_pubkey: bob_btc_address }], None)`.
4. Because `withdraw_rbf` never checks `btc_pending_info.account_id == env::predecessor_account_id()`, the call proceeds. `require_pending_sign_capacity` passes against Bob's (empty) account.
5. `withdraw_rbf_chain_specific` builds a replacement PSBT spending Alice's UTXO but paying Bob's Bitcoin address, registered under Bob's NEAR account.
6. The MPC network signs the replacement transaction.
7. Bob broadcasts it; Alice's BTC is permanently sent to Bob. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-299)
```rust
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
