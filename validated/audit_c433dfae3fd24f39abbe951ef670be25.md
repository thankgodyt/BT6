### Title
Unauthorized Refund Request Submission Allows Attacker to Block or Redirect User Refunds - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The `request_refund` function imposes no ownership or delegation check on the caller. Any unprivileged NEAR account can submit a refund request for any deposit UTXO and supply an arbitrary BTC `refund_address`. Because only one refund request may exist per UTXO, a malicious actor can front-run a legitimate depositor, block their refund, and — if the bridge fails to verify the deposit and the DAO/Operator is unresponsive for the full `unsafe_refund_timelock_sec` (14 days) — execute the refund to their own BTC address.

### Finding Description

`request_refund` is a public, permissionless function: [1](#0-0) 

The only caller-specific check is whether `gas_fee` is `Some` (lines 519–526); the `refund_address` itself is completely unconstrained when `deposit_msg.refund_address` is `None`: [2](#0-1) 

Inside `request_refund_callback`, the contract verifies the transaction is on-chain and that the output script matches the deposit address derived from `deposit_msg`, but it never checks that the caller has any relationship to the depositor: [3](#0-2) 

The duplicate-request guard then prevents any second submission for the same UTXO: [4](#0-3) 

After the `unsafe_refund_timelock_sec` window, `execute_refund` is also permissionless: [5](#0-4) 

The timelock for the "no pre-authorized address" path is the full 14-day `unsafe_refund_timelock_sec`: [6](#0-5) 

The stored `refund_address` (attacker-controlled) is what the MPC pipeline ultimately pays out to via `finalize_refund_with_psbt`: [7](#0-6) 

### Impact Explanation

**Immediate / always reachable impact (Medium):** An attacker who front-runs a legitimate depositor's `request_refund` call occupies the sole refund-request slot for that UTXO. The legitimate depositor is locked out of the refund path until the DAO/Operator manually rejects the malicious request — a stuck bridge state requiring privileged operator intervention.

**Worst-case impact (Critical):** If the bridge relayer fails to call `verify_deposit` for the targeted UTXO within 14 days *and* the DAO/Operator does not reject the malicious request, the attacker calls `execute_refund` and the MPC pipeline sends the BTC to the attacker's address. This constitutes unauthorized release of bridge-controlled BTC funds.

### Likelihood Explanation

The immediate griefing path (blocking the legitimate user's refund) is reachable by any NEAR account at the cost of the anti-spam storage deposit (`required_balance_for_request_refund`). No privileged access is required.

The full-theft path requires two additional conditions — the bridge failing to verify the deposit for 14 days and the DAO/Operator being unresponsive — making it lower probability but not impossible (e.g., during a bridge outage, a relayer bug, or a governance attack).

### Recommendation

1. **Bind the refund request to the depositor identity.** The `deposit_msg` already encodes the depositor's NEAR `account_id`. Require `env::predecessor_account_id() == deposit_msg.account_id` (or an explicit delegation) before accepting a caller-supplied `refund_address`.
2. **Alternatively, restrict the "unsafe" path to DAO/Operator.** Allow permissionless submission only when `deposit_msg.refund_address` is pre-set (the "safe" path); require a privileged role for the open-address path.
3. **Enforce a per-depositor refund-request ownership check in `execute_refund`.** Verify that the caller is either the original requester or a privileged role before allowing execution.

### Proof of Concept

```
1. User A deposits BTC to the bridge using a standard deposit message
   (deposit_msg.refund_address = None, deposit_msg.account_id = "user_a.near").

2. Attacker B observes the deposit transaction on-chain.

3. Attacker B calls:
     request_refund(
       deposit_msg = <User A's deposit_msg>,
       refund_address = "attacker_btc_address",
       tx_bytes = <User A's deposit tx>,
       vout = 0,
       proof = <valid Light Client proof>,
       gas_fee = None
     )
   attaching the required storage deposit.

4. request_refund_callback succeeds:
   - Light Client confirms the tx.
   - Output script matches the deposit address derived from deposit_msg. ✓
   - No ownership check on the caller. ✗
   - RefundRequest { refund_address: "attacker_btc_address", ... } is stored.

5. User A calls request_refund with their own BTC address.
   → Panics: "Refund request already exists for this UTXO".

6. User A is locked out. DAO/Operator must intervene to call reject_refund.

7. Worst case: bridge relayer is down, DAO/Operator is unresponsive.
   After unsafe_refund_timelock_sec (14 days), Attacker B calls execute_refund.
   MPC signs and broadcasts a transaction paying "attacker_btc_address".
   User A's BTC is stolen.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L315-325)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

```

**File:** contracts/satoshi-bridge/src/refund.rs (L516-548)
```rust
        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

```
