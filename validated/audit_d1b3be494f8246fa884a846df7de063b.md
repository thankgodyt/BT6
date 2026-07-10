### Title
Missing Ownership Check in `withdraw_rbf` Allows Any Account to RBF Another User's Pending Withdrawal - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `withdraw_rbf` function uses `env::predecessor_account_id()` as the acting account without verifying it matches the `account_id` stored in the target pending info. Any unprivileged NEAR account can call `withdraw_rbf` with another user's `original_btc_pending_verify_id`, hijacking control of that user's pending withdrawal RBF process.

### Finding Description
In `api/bridge.rs`, `withdraw_rbf` is a public, permissionless function:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();   // ← attacker's account
    self.require_pending_sign_capacity(&account_id);

    self.withdraw_rbf_chain_specific(
        account_id,                              // ← attacker passed as owner
        original_btc_pending_verify_id,          // ← victim's pending info ID
        output,
        chain_specific_data,
    );
}
``` [1](#0-0) 

Compare this with `cancel_withdraw`, which correctly derives the acting account from the stored pending info rather than from the caller:

```rust
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();                               // ← fetched from stored state
    self.require_pending_sign_capacity(&user_account_id);
    self.cancel_withdraw_chain_specific(
        user_account_id,
        ...
    );
}
``` [2](#0-1) 

`cancel_withdraw` is also gated by `#[access_control_any(roles(Role::DAO, Role::Operator))]`, while `withdraw_rbf` has no role guard at all — only a pause check. The `BTCPendingInfo` struct stores the canonical owner in `account_id`: [3](#0-2) 

### Impact Explanation
An attacker who calls `withdraw_rbf` with a victim's `original_btc_pending_verify_id` and attacker-controlled `output`:

1. Passes `require_pending_sign_capacity` against their own (attacker's) account, not the victim's.
2. Passes the attacker's `account_id` into `withdraw_rbf_chain_specific`, so the newly created RBF `BTCPendingInfo` is attributed to the attacker, not the victim.
3. The victim's original pending info is mutated (its state transitions away from `PendingSign`), removing the victim's ability to RBF or cancel their own withdrawal through normal paths.
4. The attacker now controls the RBF lifecycle (signing, further RBF, etc.) for a withdrawal they do not own.

This constitutes attacker-triggered temporary locking of bridged funds: the victim's nBTC is already locked (transferred to the bridge in `ft_on_transfer`), the original PSBT UTXOs are consumed, and the victim loses control of the RBF process. The bridge state requires operator intervention to recover.

**Impact: Medium** — Bypass of bridge policies and attacker-triggered temporary locking of bridged funds.

### Likelihood Explanation
The function is fully public with no role guard, no `#[trusted_relayer]`, and no `assert_one_yocto`. Any NEAR account can call it at any time a victim's withdrawal is in `PendingSign` stage. The only prerequisite is knowing the victim's `btc_pending_sign_id` (which is emitted as a public on-chain event via `Event::GenerateBtcPendingInfo`). [4](#0-3) 

**Likelihood: High** — No privilege required; pending IDs are publicly observable from emitted events.

### Recommendation
Mirror the pattern used in `cancel_withdraw`: derive the acting account from the stored `BTCPendingInfo.account_id` and verify it matches `env::predecessor_account_id()` before proceeding. Additionally, add `assert_one_yocto()` and consider whether `#[access_control_any]` or `#[trusted_relayer]` is appropriate, consistent with the rest of the privileged RBF surface.

### Proof of Concept

1. Victim calls `ft_transfer_call` → bridge creates `BTCPendingInfo` with `account_id = victim`, emits `GenerateBtcPendingInfo { btc_pending_id: "abc123" }`.
2. Attacker observes the event and calls:
   ```
   withdraw_rbf(
     original_btc_pending_verify_id: "abc123",
     output: [TxOut { value: ..., script_pubkey: attacker_chosen_script }],
     chain_specific_data: None
   )
   ```
3. Inside `withdraw_rbf`: `account_id = attacker`. `require_pending_sign_capacity(attacker)` passes (attacker has no pending txs). `withdraw_rbf_chain_specific(attacker, "abc123", ...)` is called.
4. A new RBF `BTCPendingInfo` is created with `account_id = attacker`. The victim's original pending info state is mutated.
5. The victim can no longer call `withdraw_rbf` on their own pending info (state has changed). The attacker controls the RBF signing pipeline for the victim's withdrawal. The victim's nBTC remains locked in the bridge until an operator intervenes.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L135-139)
```rust
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
```
