### Title
Unpermissioned `request_refund` Allows Attacker to Redirect BTC Refund to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

`request_refund` carries no caller-identity check. Any NEAR account can submit a refund request for any valid BTC deposit UTXO and supply an arbitrary `refund_address`. Because the first request for a given UTXO wins and subsequent calls are rejected, an attacker who races the legitimate depositor can permanently redirect the BTC refund to an address they control.

### Finding Description

`request_refund` is decorated only with `#[pause(except(roles(Role::DAO)))]` — there is no `#[access_control_any]` guard and no check that the caller is the intended recipient of the refund. [1](#0-0) 

The function accepts a caller-supplied `refund_address` and uses it verbatim when `deposit_msg.refund_address` is `None`: [2](#0-1) 

In `request_refund_callback`, the only duplicate guard is a key-existence check — the first request for a UTXO is stored and all later ones are rejected: [3](#0-2) 

The stored `refund_address` is later used verbatim to build the refund output that the MPC network signs: [4](#0-3) 

`get_user_deposit_address` emits a `LogDepositAddress` event that exposes the full `deposit_msg` on-chain, giving an attacker everything needed to reconstruct the call: [5](#0-4) 

### Impact Explanation

An attacker who races the depositor's `request_refund` call (or simply calls it first, having observed the `LogDepositAddress` event and the on-chain BTC transaction) can:

1. Submit `request_refund(deposit_msg, attacker_btc_address, tx_bytes, vout, proof, None)`.
2. The legitimate user's subsequent call fails with `"Refund request already exists for this UTXO"`.
3. After `unsafe_refund_timelock_sec` elapses, the attacker (or anyone) calls `execute_refund`, which builds and MPC-signs a transaction paying the attacker's address.
4. The depositor's BTC is permanently transferred to the attacker.

`execute_refund` is also unpermissioned (beyond the pause guard), so the attacker can trigger it themselves: [6](#0-5) 

**Impact: Critical** — direct, permanent theft of user BTC funds.

### Likelihood Explanation

The `deposit_msg` is broadcast in a `LogDepositAddress` event every time a user queries their deposit address. The BTC transaction is public on the Bitcoin blockchain. An attacker passively monitoring both chains has all inputs needed to call `request_refund` before the depositor. The only cost is the small NEAR storage deposit required by the function. The `unsafe_refund_timelock_sec` gives DAO/Operator a window to reject, but if they are unavailable or inattentive the theft completes. **Likelihood: Medium.**

### Recommendation

Restrict `request_refund` so that only the account whose `deposit_msg.recipient_id` matches `env::predecessor_account_id()` (or a whitelisted relayer) may submit a refund request for a given UTXO. Alternatively, require that `deposit_msg.refund_address` is always pre-set (non-`None`) so the refund destination is committed at deposit-address-generation time and cannot be overridden by a third party.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: alice, refund_address: None, … })`. The `LogDepositAddress` event is emitted with the full `deposit_msg`.
2. Alice sends BTC to the returned address. The transaction is confirmed on Bitcoin.
3. Attacker observes the event and the BTC transaction. Attacker calls:
   ```
   request_refund(
     deposit_msg = <alice's deposit_msg>,
     refund_address = "attacker_btc_address",
     tx_bytes = <alice's tx>,
     vout = 0,
     proof = <valid merkle proof>,
     gas_fee = None
   )
   ```
   with the required NEAR storage deposit attached.
4. `request_refund_callback` validates the output script against `deposit_msg` (passes, because `deposit_msg` is unchanged), stores the request with `refund_address = attacker_btc_address`.
5. Alice calls `request_refund` — it panics: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec`, attacker calls `execute_refund(utxo_storage_key, None)`. The MPC network signs a transaction paying `attacker_btc_address`. Alice's BTC is stolen. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-518)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
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
