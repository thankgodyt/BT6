### Title
Per-Account Pending Sign Limit Bypassed via nBTC Transfer to Fresh Accounts - (File: `contracts/satoshi-bridge/src/api/token_receiver.rs`)

### Summary
The bridge enforces a per-account cap on concurrent pending withdrawal sign transactions (`pending_tx_limits`, default 1). Because nBTC is a freely transferable NEP-141 token, any holder can split their balance across multiple fresh NEAR accounts and initiate one withdrawal from each, bypassing the intended limit entirely.

### Finding Description
When a user initiates a withdrawal they call `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)`. The nBTC contract fires `ft_on_transfer` on the bridge with `sender_id` equal to the calling account. Inside `create_btc_pending_info`, the bridge checks:

```rust
let max_pending = self.get_max_pending_sign_txs(&sender_id);
let account = self.internal_unwrap_or_create_mut_account(&sender_id);
require!(
    account.pending_sign_count() < max_pending,
    "Too many pending sign transactions"
);
``` [1](#0-0) 

The limit is looked up and enforced exclusively against `sender_id` — the NEAR account that called `ft_transfer_call`. The default cap is 1:

```rust
pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
    self.data()
        .pending_tx_limits
        .get(account_id)
        .copied()
        .unwrap_or(1)
}
``` [2](#0-1) 

Meanwhile, nBTC is a standard NEP-141 token with unrestricted `ft_transfer`:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    ...
    self.token.ft_transfer(receiver_id, amount, memo);
}
``` [3](#0-2) 

A fresh NEAR account has no entry in `btc_pending_sign_ids`, so `pending_sign_count()` returns 0 and the check always passes for it. [4](#0-3) 

### Impact Explanation
An attacker holding nBTC can:
1. Transfer portions of their balance to N freshly created NEAR accounts.
2. Call `ft_transfer_call` from each account with a valid `Withdraw` message.
3. Each call passes the `pending_sign_count < max_pending` check because each account starts at 0.
4. N UTXOs are simultaneously locked in `btc_pending_infos` and removed from the available UTXO pool.

If the attacker uses enough accounts to exhaust the bridge's available UTXO set, no other user can initiate a withdrawal until those pending transactions are signed, verified, or timed out. This constitutes an attacker-triggered temporary locking of bridged funds and a bypass of the bridge's per-account pending-sign policy.

**Impact: Medium** — Bypass of bridge limits/policies; attacker-triggered temporary locking of other users' withdrawal capability.

### Likelihood Explanation
Creating additional NEAR accounts costs a trivial amount of NEAR (storage deposit). Any nBTC holder can execute this attack with no special privileges. The only prerequisite is holding enough nBTC to meet `min_withdraw_amount` per account, which is a normal user capability. Likelihood is **High**.

### Recommendation
Track the pending sign count against the *original depositor identity* rather than (or in addition to) the immediate `sender_id`, or enforce the limit at the nBTC token level by restricting transfers when the sender has an active pending sign. A simpler mitigation is to enforce a global cap on total pending sign transactions, independent of per-account limits, so that exhausting the UTXO pool via many accounts is impossible regardless of how the tokens are distributed.

### Proof of Concept
1. Assume `pending_tx_limits` default = 1 and the bridge has 5 available UTXOs.
2. Attacker holds 5 × `min_withdraw_amount` nBTC in account `attacker.near`.
3. Attacker registers accounts `a1.near` … `a5.near` and calls `nbtc.storage_deposit` for each.
4. Attacker calls `nbtc.ft_transfer(a1.near, min_withdraw_amount)` … `ft_transfer(a5.near, min_withdraw_amount)`.
5. From each `aN.near`, attacker calls `nbtc.ft_transfer_call(bridge, min_withdraw_amount, WithdrawMsg{...})`.
6. Each call reaches `create_btc_pending_info` with `sender_id = aN.near`; `pending_sign_count()` = 0 < 1, so the check passes.
7. All 5 UTXOs are now locked in pending sign state; legitimate users calling `ft_transfer_call` receive "Invalid amount" or find no UTXOs available, blocking withdrawals until the attacker's transactions are resolved. [5](#0-4) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L70-140)
```rust
impl Contract {
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

**File:** contracts/satoshi-bridge/src/account.rs (L99-101)
```rust
    pub fn pending_sign_count(&self) -> u32 {
        u32::try_from(self.btc_pending_sign_ids.len()).unwrap_or(u32::MAX)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L105-111)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }
```

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```
