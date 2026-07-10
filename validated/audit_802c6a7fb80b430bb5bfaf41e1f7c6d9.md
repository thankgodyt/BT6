Now I have all the code needed to evaluate this claim. Let me trace the exact path.

Now I have all the code needed. Let me trace the exact execution path.

**Key facts from the code:**

**1. `request_refund` is publicly callable** — it is in a `#[trusted_relayer]` impl block, but the function itself has no `#[trusted_relayer]` attribute (unlike `verify_refund_finalize` and `remove_refund_pending_tx_id` in the same block, which do). The pattern in the first impl block confirms this: `get_user_deposit_address` and `get_change_address` in the same `#[trusted_relayer]` block have no individual guard and are clearly public. [1](#0-0) 

**2. The `refund_address` guard only fires when `deposit_msg.refund_address` is `Some`:** [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller-supplied `refund_address` string is accepted without any check.

**3. `get_deposit_path` excludes `refund_address` from the hash when it is `None`** due to `#[serde(skip_serializing_if = "Option::is_none")]`: [3](#0-2) [4](#0-3) 

So `get_deposit_path(DepositMsg{refund_address: None, ...})` produces the same hash as the victim's original deposit path.

**4. `request_refund_callback` verifies the script_pubkey against the path derived from `deposit_msg`**, then stores the caller-supplied `refund_address` verbatim: [5](#0-4) [6](#0-5) 

**5. The only mitigation is `unsafe_refund_timelock_sec` + DAO/Operator rejection:** [7](#0-6) 

The comment explicitly acknowledges the risk: "Refund address supplied by caller of `request_refund`: longer timelock to give DAO/Operator time to reject suspicious requests."

**Critical gap in the mitigation:** The DAO/Operator has **no on-chain way to verify** whether the submitted `refund_address` is legitimate. When `deposit_msg.refund_address` is `None`, there is no pre-authorized address to compare against. The operator would need off-chain communication with the victim to verify the address — which is operationally unreliable. Furthermore, once the attacker's request is stored, the victim is **locked out** from submitting their own refund request for the same UTXO: [8](#0-7) 

---

### Title
Unprivileged Attacker Can Redirect Victim's BTC Refund to Attacker-Controlled Address via `request_refund` with `deposit_msg.refund_address = None` — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
When a victim deposits BTC using a `DepositMsg` with `refund_address: None`, any unprivileged caller can front-run the victim's refund request by submitting `request_refund` with the same `DepositMsg` but an attacker-controlled `refund_address`. The script_pubkey check passes because `refund_address: None` is excluded from the path hash. The stored `RefundRequest` carries the attacker's address. After `unsafe_refund_timelock_sec` elapses, `execute_refund` sends the victim's BTC to the attacker.

### Finding Description
`get_deposit_path` serializes `DepositMsg` to JSON and SHA-256 hashes it. The `refund_address` field carries `#[serde(skip_serializing_if = "Option::is_none")]`, so when it is `None` it is absent from the JSON and therefore absent from the path hash. [3](#0-2) [4](#0-3) 

`internal_request_refund` only enforces the `refund_address` parameter when `deposit_msg.refund_address` is `Some`. When it is `None`, the caller-supplied string is accepted unconditionally: [2](#0-1) 

`request_refund_callback` recomputes the path from the attacker-supplied `deposit_msg`, derives the deposit address, and checks that the on-chain output's `script_pubkey` matches. Because the victim's original `DepositMsg` also had `refund_address: None`, the hashes are identical and the check passes. The callback then stores the attacker-controlled `refund_address` in the `RefundRequest`: [5](#0-4) [6](#0-5) 

Once stored, the victim cannot submit their own refund request for the same UTXO (duplicate guard at line 544–547). The victim is locked out until the DAO/Operator rejects the attacker's request. After `unsafe_refund_timelock_sec`, `execute_refund` builds a PSBT paying `refund_request.refund_address` — the attacker's address — and routes it through the MPC signing pipeline: [9](#0-8) 

### Impact Explanation
The victim's entire deposit UTXO (minus gas fee) is sent to the attacker's BTC address. This is a direct, permanent theft of user funds. The victim has no on-chain recourse once the attacker's request is stored and the DAO/Operator fails to reject it.

### Likelihood Explanation
The preconditions are realistic and common:
- Many users will deposit without pre-authorizing a `refund_address` (the field is optional and its security implications are not obvious).
- The victim's `DepositMsg` is publicly visible on NEAR (passed as a transaction argument to `verify_deposit_v2` or emitted via `LogDepositAddress`).
- The attacker only needs to observe the victim's BTC deposit transaction and the corresponding NEAR `DepositMsg`, then call `request_refund` before the victim does.

The DAO/Operator mitigation is structurally insufficient: when `deposit_msg.refund_address` is `None`, there is no on-chain pre-authorized address to compare against. The operator cannot distinguish a legitimate request from a malicious one without off-chain communication with the victim for every such request — an operationally unreliable requirement.

### Recommendation
Require that `request_refund` can only be called by the `deposit_msg.recipient_id` (the NEAR account that was to receive nBTC) when `deposit_msg.refund_address` is `None`. This ties the refund address authorization to the NEAR account that initiated the deposit, without requiring a pre-authorized BTC address. Alternatively, require `deposit_msg.refund_address` to always be `Some` and enforce it strictly, removing the open-ended caller-supplied path entirely.

### Proof of Concept
1. Victim generates deposit address: `get_user_deposit_address(DepositMsg{recipient_id: "victim.near", refund_address: None, ...})` → `addr_V`.
2. Victim sends 1 BTC to `addr_V` on Bitcoin. The deposit is never finalized (relayer does not call `verify_deposit_v2`).
3. Attacker observes the victim's `DepositMsg` from NEAR transaction history and the BTC `tx_bytes`/`vout`.
4. Attacker calls `request_refund(deposit_msg=DepositMsg{recipient_id:"victim.near", refund_address:None,...}, refund_address="attacker_btc_addr", tx_bytes=<victim_tx>, vout=0, proof=<valid_proof>, gas_fee=None)`.
5. `request_refund_callback` computes `get_deposit_path(deposit_msg)` → same hash as victim's path → `script_pubkey` check passes → `RefundRequest{refund_address:"attacker_btc_addr"}` is stored.
6. Victim attempts `request_refund` with their own address → panics: "Refund request already exists for this UTXO".
7. After `unsafe_refund_timelock_sec`, attacker calls `execute_refund(utxo_storage_key)`.
8. `internal_execute_refund` calls `build_refund_output("attacker_btc_addr", refund_amount)` → PSBT signed by MPC → 1 BTC (minus fee) sent to attacker's address.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-535)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──

    /// Submit a refund request for a deposit that was never finalized via `verify_deposit` or `safe_verify_deposit`.
    /// The BTC transaction is verified through the Light Client to prove the deposit exists.
    /// After the timelock period, anyone can call `execute_refund` to initiate the return.
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - The original deposit message. If `deposit_msg.refund_address` is set,
    ///   it must match the provided `refund_address`.
    /// * `refund_address` - BTC address to send the refund to. If `deposit_msg.refund_address`
    ///   is `None`, this value is used directly.
    /// * `tx_bytes` - BTC transaction bytes proving the deposit.
    /// * `vout` - Output index of the deposit in the transaction.
    /// * `proof` - Transaction inclusion proof for Light Client verification, bundling:
    ///   `tx_block_blockhash` (block hash containing the transaction), `tx_index`
    ///   (transaction index within the block), `merkle_proof` (Merkle proof of the
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    /// * `gas_fee` - Optional custom gas fee. Only DAO or Operator can set this.
    ///   If `None`, the default `config.max_btc_gas_fee` is used during `execute_refund`.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-228)
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
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L517-525)
```rust
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-27)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-43)
```rust
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```
