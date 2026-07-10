Now I have all the information needed. Let me trace the complete execution path.

**Key facts established:**

1. `sign_btc_transaction_callback` removes the tx ID from `btc_pending_sign_ids` when all inputs are signed and the tx moves to `PendingVerify` stage. [1](#0-0) 

2. `withdraw_rbf` calls `require_pending_sign_capacity` before creating the RBF pending info — checking `btc_pending_sign_ids.len() < max_pending`. [2](#0-1) [3](#0-2) 

3. The default `max_pending_sign_txs` is **1**. [4](#0-3) 

4. The `define_rbf_method!` macro inserts the new RBF tx ID into `btc_pending_sign_ids` **after** the internal function returns — meaning the capacity check fires before the slot is consumed. [5](#0-4) 

---

### Title
`withdraw_rbf` blocked by unrelated pending-sign slot — user cannot accelerate stuck withdrawal — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/account.rs`)

### Summary

`withdraw_rbf` calls `require_pending_sign_capacity` before creating the RBF pending-sign entry. This check counts all entries in `btc_pending_sign_ids`. Because the original withdrawal is removed from `btc_pending_sign_ids` when it moves to `PendingVerify`, a second unrelated withdrawal in `PendingSign` state occupies the only available slot, causing `withdraw_rbf` to revert with "Too many pending sign transactions" even though the user owns the stuck withdrawal and is entitled to accelerate it.

### Finding Description

The lifecycle of a withdrawal is:

1. `create_btc_pending_info` → inserts tx ID into `btc_pending_sign_ids` (stage: `PendingSign`).
2. `sign_btc_transaction_callback` (all inputs signed) → **removes** tx ID from `btc_pending_sign_ids`, moves to `PendingVerify`, inserts into `btc_pending_verify_list`. [1](#0-0) 

3. User calls `withdraw_rbf` on the `PendingVerify` tx → `require_pending_sign_capacity` fires, counting `btc_pending_sign_ids.len()`. [6](#0-5) 

**Concrete reachable scenario (no elevated limits required):**

| Step | Action | `btc_pending_sign_ids` | Count | Limit |
|------|--------|----------------------|-------|-------|
| 1 | User creates TX1 (withdrawal) | `{TX1}` | 1 | 1 |
| 2 | TX1 fully signed → PendingVerify | `{}` | 0 | 1 |
| 3 | User creates TX2 (new withdrawal) | `{TX2}` | 1 | 1 |
| 4 | TX1 stuck on BTC; user calls `withdraw_rbf(TX1)` | `{TX2}` | 1 | 1 |
| 5 | `require_pending_sign_capacity`: `1 < 1` → **REVERT** | — | — | — |

The RBF tx would itself become a new `PendingSign` entry (inserted by `define_rbf_method!` after the internal call), which is why the capacity check exists — but it does not distinguish between creating a brand-new original withdrawal and accelerating an already-committed one. [7](#0-6) 

`cancel_withdraw` (DAO/Operator only) has the same guard: [8](#0-7) 

So the user cannot RBF and cannot self-cancel; only DAO/Operator can cancel.

### Impact Explanation

The user's TX1 is stuck in `PendingVerify` (unconfirmed on Bitcoin). They cannot call `withdraw_rbf` to increase the fee-rate because TX2 occupies the single pending-sign slot. The user's bridged funds remain locked in the unconfirmed Bitcoin transaction until either:
- TX2 is signed by MPC and moves to `PendingVerify` (freeing the slot), or
- A DAO/Operator calls `cancel_withdraw`.

If MPC signing is delayed or TX2 is itself stuck, both withdrawals are simultaneously blocked. This is a **temporary locking of bridged funds** requiring operator intervention, matching the Medium impact category.

### Likelihood Explanation

This is reachable by any user who has submitted two sequential withdrawals — a common pattern for active bridge users. No elevated privileges, no DAO interaction, and no special configuration are required. The default `pending_tx_limit` of 1 is sufficient to trigger the condition. [4](#0-3) 

### Recommendation

`withdraw_rbf` (and `cancel_withdraw`) should bypass the `require_pending_sign_capacity` check, or use a separate, higher limit for RBF operations. The capacity guard is appropriate for creating new original withdrawals but must not block acceleration of an already-committed withdrawal. One approach: skip the check entirely in `withdraw_rbf` since the RBF tx replaces an existing pending-verify entry rather than consuming a new user-initiated slot.

### Proof of Concept

```
1. Alice submits withdrawal TX1 via ft_on_transfer → btc_pending_sign_ids = {TX1}
2. Relayer calls sign_btc_transaction(TX1, 0) → all inputs signed
   → btc_pending_sign_ids = {}, btc_pending_verify_list = {TX1}
3. Alice submits withdrawal TX2 via ft_on_transfer → btc_pending_sign_ids = {TX2}
4. TX1 is unconfirmed on Bitcoin (low fee). Alice calls:
     withdraw_rbf(original_btc_pending_verify_id = TX1, output = [...])
5. require_pending_sign_capacity fires:
     pending_sign_count() = 1 (TX2 in btc_pending_sign_ids)
     max_pending = 1
     1 < 1 → false → panic "Too many pending sign transactions"
6. Alice cannot accelerate TX1. Funds locked until TX2 is signed or DAO intervenes.
```

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L195-207)
```rust
                btc_pending_info.to_pending_verify_stage();

                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L259-274)
```rust
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

**File:** contracts/satoshi-bridge/src/account.rs (L104-111)
```rust
impl Contract {
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L9-43)
```rust
macro_rules! define_rbf_method {
    ($method:ident, $internal_fn:ident) => {
        pub(crate) fn $method(
            &mut self,
            account_id: AccountId,
            original_btc_pending_verify_id: String,
            output: Vec<TxOut>,
            _chain_specific_data: Option<ChainSpecificData>,
        ) {
            let predecessor_account_id = env::predecessor_account_id();
            let original_tx_btc_pending_info =
                self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);

            let new_psbt = self.generate_psbt_from_original_psbt_and_new_output(
                original_tx_btc_pending_info,
                output,
            );

            let btc_pending_id = self.$internal_fn(
                &account_id,
                original_btc_pending_verify_id,
                new_psbt,
                predecessor_account_id,
            );

            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());

            Event::GenerateBtcPendingInfo {
                account_id: &account_id,
                btc_pending_id: &btc_pending_id,
            }
            .emit();
        }
```
