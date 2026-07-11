### Title
Attacker Can Front-Run `request_refund` to Redirect BTC Refunds to an Arbitrary Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `request_refund` function is publicly callable by any NEAR account and does not bind the caller-supplied `refund_address` to the original depositor when `deposit_msg.refund_address` is `None`. An attacker who observes a legitimate user's pending `request_refund` call can race to register the same UTXO's refund request first, substituting their own BTC address. The duplicate-request guard then blocks the legitimate user's callback, and after the `unsafe_refund_timelock_sec` elapses the attacker can execute the refund and receive the victim's BTC.

### Finding Description

`request_refund` sits inside the `#[trusted_relayer] #[near] impl Contract` block that begins at line 480 of `api/bridge.rs`, but it carries **no individual `#[trusted_relayer]` attribute** of its own. [1](#0-0) 

The pattern throughout the file makes the semantics clear: only functions that carry their own `#[trusted_relayer]` attribute are gated to whitelisted relayers. Functions without it — `withdraw_rbf`, `execute_refund`, `request_refund`, `reject_refund` — are publicly callable. `withdraw_rbf` is an obvious user-facing function that would be broken if the impl-level attribute restricted all methods, confirming the interpretation. [2](#0-1) 

Inside `request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` (the common case — the field is optional and skipped in serialization), **any caller may supply any BTC address**. There is no check that `env::predecessor_account_id()` matches the original depositor.

The duplicate-request guard lives in the async callback, not in the entry point:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

Because both the legitimate user's call and the attacker's call pass the initial entry-point checks and each independently dispatch a cross-contract light-client verification, whichever callback lands first wins. The loser's callback is rejected with the duplicate error, permanently blocking that UTXO from a second `request_refund` until the winning request is rejected by the DAO/Operator.

Once the attacker's request is registered, `execute_refund` is also publicly callable: [5](#0-4) 

After `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund`, which builds a PSBT paying `refund_amount` to the attacker's stored `refund_address`: [6](#0-5) 

The MPC then signs and broadcasts the transaction, sending the victim's BTC to the attacker.

### Impact Explanation

If the DAO/Operator does not detect and reject the attacker's request within `unsafe_refund_timelock_sec`, the victim's entire deposited BTC is transferred to the attacker's address. This is a direct, complete theft of user funds — a Critical impact under "Significant loss, theft, destruction, or permanent locking of user or protocol funds."

Even when the DAO/Operator does intervene, the victim suffers: their own `request_refund` callback was already rejected, their attached storage deposit is consumed, and they must restart the entire refund flow from scratch, waiting through the full timelock again.

### Likelihood Explanation

All inputs the attacker needs are public:
- `deposit_msg` is derived from the deposit address path and is observable on-chain or from bridge events.
- `tx_bytes` and `vout` are on the Bitcoin blockchain.
- `proof` can be constructed by any party with access to a Bitcoin node.

The attacker only needs to submit their `request_refund` call before the victim's cross-contract callback resolves. Because `request_refund` dispatches an async light-client call, there is a multi-block window during which the attacker can race. On NEAR, transaction ordering within a block is validator-controlled, making this a realistic race condition. The attacker's only cost is the storage deposit required by `required_balance_for_request_refund`, which is small relative to any meaningful BTC deposit.

### Recommendation

Bind the `refund_address` to the depositor at registration time. Two complementary approaches:

1. **Require `deposit_msg.refund_address` to be set** when `request_refund` is called by an unprivileged account. If the depositor did not pre-authorize a refund address in their `deposit_msg`, only DAO/Operator should be allowed to supply one.

2. **Record `env::predecessor_account_id()` as the refund requester** in `RefundRequest`, and require that only the original requester (or DAO/Operator) can call `execute_refund` for that request. This mirrors the Chainlink fix: binding the request ID to the sender so no third party can hijack it.

### Proof of Concept

1. Alice deposits BTC. Her `deposit_msg` has `refund_address: None`. The deposit is never finalized.
2. Alice calls `request_refund(deposit_msg, alice_btc_addr, tx_bytes, vout, proof, None)` with her BTC address.
3. Attacker observes Alice's NEAR transaction and immediately calls `request_refund(deposit_msg, attacker_btc_addr, tx_bytes, vout, proof, None)` with the attacker's BTC address.
4. Both calls pass the entry-point checks and dispatch light-client verification cross-contract calls.
5. The attacker's `request_refund_callback` resolves first. The attacker's `RefundRequest` is stored with `refund_address = attacker_btc_addr`.
6. Alice's `request_refund_callback` resolves and panics: `"Refund request already exists for this UTXO"`. Alice's storage deposit is consumed.
7. After `unsafe_refund_timelock_sec` (assuming DAO/Operator does not reject), the attacker calls `execute_refund(utxo_storage_key, None)`.
8. `finalize_refund_with_psbt` builds a PSBT paying `refund_amount` to `attacker_btc_addr`. The MPC signs it. The signed transaction is broadcast. Alice's BTC arrives at the attacker's address.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
