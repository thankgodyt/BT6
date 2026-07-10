### Title
Attacker Can Redirect Any Unfinalized BTC Deposit to an Arbitrary Address via Unchecked `refund_address` in `request_refund` - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `request_refund` function is publicly callable by any NEAR account and accepts an arbitrary `refund_address` with no ownership check on the deposit. An attacker who observes an unfinalized BTC deposit can submit a refund request pointing to their own Bitcoin address, wait out the timelock, and execute the refund — stealing the victim's BTC.

### Finding Description
`request_refund` (bridge.rs:510–535) is in a `#[trusted_relayer]` impl block but carries no `#[trusted_relayer]` attribute at the function level — only `#[payable]` and `#[pause]`. Per the wiki ("Any user can call `request_refund`") and the code, it is fully public.

The function accepts a caller-supplied `refund_address`. The only guard is:

```rust
// refund.rs:154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None` — the standard case for ordinary deposits — **any BTC address is accepted without restriction**. There is no check that the caller's NEAR account matches the depositor's account ID embedded in `deposit_msg`.

The `deposit_msg` is public: it is emitted as a NEAR event in `get_user_deposit_address` (bridge.rs:462–472) and is also visible in the relayer's `verify_deposit` call arguments on-chain.

The `execute_refund` function (bridge.rs:582–589) is likewise public (no `#[trusted_relayer]` at function level). After calling `execute_refund`, the attacker becomes the `account_id` of the resulting `BTCPendingInfo` (refund.rs:344–345), giving them the right to call `sign_btc_transaction` and drive the MPC signing pipeline.

The only mitigation is `unsafe_refund_timelock_sec` (refund.rs:226–227), which gives DAO/Operator a window to call `reject_refund`. This is not a cryptographic or protocol-level fix — it relies entirely on off-chain monitoring and timely human intervention.

**Attack chain:**
1. Victim calls `get_user_deposit_address` with `deposit_msg = {account_id: "victim.near", refund_address: None, …}`. The full `deposit_msg` is emitted as a NEAR event.
2. Victim sends BTC to the derived deposit address.
3. Relayer is slow, offline, or the attacker front-runs `verify_deposit`.
4. Attacker calls `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)`. The callback stores a `RefundRequest` with `refund_address = "attacker_btc_addr"` (refund.rs:564–578).
5. After `unsafe_refund_timelock_sec` elapses, attacker calls `execute_refund(utxo_storage_key, None)`. A `BTCPendingInfo` is created with `account_id = attacker` (refund.rs:344).
6. Attacker calls `sign_btc_transaction` as the owner of the pending info; MPC signs the PSBT paying `attacker_btc_addr`.
7. Signed transaction is broadcast to Bitcoin. A trusted relayer calls `verify_refund_finalize`, which confirms inclusion and cleans up state (refund.rs:462–493).
8. Victim's BTC arrives at the attacker's address; victim receives nothing.

### Impact Explanation
**Critical — Significant theft of user funds.** Any BTC deposited to a standard bridge address (with `deposit_msg.refund_address = None`) is at risk of being stolen via a fraudulent refund request. The attacker receives the full deposit minus the gas fee; the victim loses their entire deposit. No privileged access is required.

### Likelihood Explanation
**Medium.** The `deposit_msg` is public on-chain. The attacker only needs to monitor NEAR events or mempool activity, identify an unprocessed deposit, and submit a refund request before `verify_deposit` is called. The `unsafe_refund_timelock_sec` window requires active DAO/Operator monitoring to be effective; if monitoring lapses or the timelock is short, the attack succeeds silently.

### Recommendation
- **Require a pre-authorized refund address:** Enforce that `deposit_msg.refund_address` is always set, so the refund destination is committed at deposit time and cannot be overridden by a third party.
- **Bind the refund request to the depositor's NEAR account:** Verify that `env::predecessor_account_id()` matches the `account_id` field in `deposit_msg` before accepting the request.
- **Restrict `request_refund` to trusted relayers:** Add `#[trusted_relayer]` at the function level, consistent with `verify_deposit` and `verify_refund_finalize`.

### Proof of Concept

```
// 1. Victim generates deposit address (deposit_msg emitted as NEAR event)
satoshi_bridge.get_user_deposit_address({account_id: "victim.near", refund_address: null, ...})

// 2. Victim sends 1 BTC to the derived address on Bitcoin.

// 3. Attacker observes the NEAR event, reads deposit_msg and tx_bytes from chain.

// 4. Attacker submits fraudulent refund request (no ownership check):
satoshi_bridge.request_refund(
    deposit_msg = <victim's deposit_msg>,
    refund_address = "attacker_btc_address",
    tx_bytes = <victim's tx_bytes>,
    vout = 0,
    proof = <valid inclusion proof>,
    gas_fee = null,
    attached_deposit = required_balance_for_request_refund()
)
// → RefundRequest stored with refund_address = "attacker_btc_address"

// 5. After unsafe_refund_timelock_sec (DAO/Operator does not reject):
satoshi_bridge.execute_refund(utxo_storage_key = "<txid>@0", chain_specific_data = null)
// → BTCPendingInfo created with account_id = attacker

// 6. Attacker signs via MPC:
satoshi_bridge.sign_btc_transaction(sign_index = 0, btc_pending_id = "<psbt_id>")

// 7. Signed tx broadcast; trusted relayer finalizes:
satoshi_bridge.verify_refund_finalize(tx_id = "<refund_txid>", proof = <proof>)
// → 1 BTC (minus gas fee) delivered to attacker_btc_address
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L510-535)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-345)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```
