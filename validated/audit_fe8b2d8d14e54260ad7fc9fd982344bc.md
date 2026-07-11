### Title
Missing Ownership Check on `withdraw_rbf` Allows Any Caller to Trigger RBF on Another User's Pending Withdrawal - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The public `withdraw_rbf` function accepts an arbitrary `original_btc_pending_verify_id` and caller-supplied `output` values, but never verifies that `env::predecessor_account_id()` is the owner of that pending transaction. Any unprivileged NEAR account can invoke `withdraw_rbf` against a victim's in-flight withdrawal, passing attacker-controlled outputs, with no rate limit, no ownership gate, and no attached-deposit requirement.

### Finding Description
`withdraw_rbf` is declared with no access-control decorator and no `assert_one_yocto` guard:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();   // ← attacker's own account
    self.require_pending_sign_capacity(&account_id);  // ← checks attacker's quota, not victim's
    self.withdraw_rbf_chain_specific(
        account_id,                                   // ← attacker's id forwarded as owner
        original_btc_pending_verify_id,               // ← victim's pending tx id
        output,                                       // ← attacker-controlled outputs
        chain_specific_data,
    );
}
``` [1](#0-0) 

The `BTCPendingInfo` struct records the true owner in `account_id`: [2](#0-1) 

There is no step between lines 265–273 that reads `btc_pending_infos[original_btc_pending_verify_id].account_id` and compares it to `env::predecessor_account_id()`. Contrast this with the privileged `cancel_withdraw`, which correctly fetches the owner from the pending info before acting:

```rust
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
self.require_pending_sign_capacity(&user_account_id);   // ← victim's quota, not caller's
``` [3](#0-2) 

The attacker's `account_id` is forwarded into `withdraw_rbf_chain_specific` as the new pending-info owner, while the attacker freely supplies the `output` vector (the replacement transaction outputs). The only guard is `require_pending_sign_capacity` checked against the **attacker's** account, whose default limit is 1: [4](#0-3) 

### Impact Explanation
Two impact tiers exist depending on whether `withdraw_rbf_chain_specific` re-validates outputs against the original recipient:

**Critical path** — If the replacement outputs are not re-checked against the original withdrawal target, the attacker supplies a `TxOut` paying their own Bitcoin address. The MPC service signs the attacker-authored PSBT (it only verifies the NEAR-side PSBT structure, not the economic intent). Once broadcast and confirmed, the victim's BTC is delivered to the attacker. The victim's nBTC was already burned at `ft_on_transfer` time, so the loss is permanent.

**Medium path** — Even if outputs are re-validated, the attacker creates a new `BTCPendingInfo` attributed to themselves for the victim's UTXO set. This puts the bridge into a split state: the victim's original pending entry and the attacker's RBF entry both reference the same UTXOs. The victim's withdrawal is effectively hijacked and stuck, requiring operator intervention to resolve.

Both paths fall within the allowed impact scope (critical: unauthorized redirection of bridge-controlled funds; medium: attacker-triggered temporary locking / stuck bridge state requiring operator intervention).

### Likelihood Explanation
All pending transaction IDs are deterministic hashes of PSBT payload preimages and are observable via NEAR RPC (`get_btc_pending_info` view calls or on-chain events emitted at withdrawal initiation). Any NEAR account can call `withdraw_rbf` with zero attached deposit and only needs to hold enough NEAR for gas. The attacker's pending-sign quota (default 1) is the only throttle, and it applies to the attacker's own account — not the victim's — so it does not prevent the attack.

### Recommendation
Add an ownership assertion immediately after fetching `account_id`:

```rust
pub fn withdraw_rbf(...) {
    let account_id = env::predecessor_account_id();
    let pending_info = self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
    require!(
        pending_info.account_id == account_id,
        "Only the withdrawal owner can submit an RBF"
    );
    self.require_pending_sign_capacity(&account_id);
    ...
}
```

This mirrors the pattern already used in `cancel_withdraw` (operator-only) and closes the missing authorization gate on the user-facing RBF path.

### Proof of Concept

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → `create_btc_pending_info`. Her withdrawal is recorded with `btc_pending_id = H` and `account_id = alice.near`. Her nBTC is held/burned.
2. Bob queries `get_btc_pending_info(H)` via NEAR RPC and learns Alice's pending ID.
3. Bob calls `withdraw_rbf(original_btc_pending_verify_id = H, output = [TxOut { value: alice_amount - fee, script_pubkey: bob_btc_address }])`.
4. No ownership check fires. `require_pending_sign_capacity` passes against Bob's own (empty) account.
5. `withdraw_rbf_chain_specific(bob.near, H, bob_outputs, ...)` creates a new `BTCPendingInfo` attributed to Bob, spending Alice's UTXOs, paying Bob's Bitcoin address.
6. MPC signs the PSBT. The signed transaction is broadcast. Alice's BTC arrives at Bob's address. Alice's nBTC is already gone. [1](#0-0) [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/account.rs (L105-123)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }

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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L71-140)
```rust
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```
