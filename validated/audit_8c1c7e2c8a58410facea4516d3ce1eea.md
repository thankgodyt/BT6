### Title
Unprivileged Caller Can Hijack Any Unverified Deposit's Refund Address via `request_refund`, Enabling BTC Theft After the Unsafe Timelock - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` imposes no ownership check on the caller: any NEAR account can submit a refund request for a deposit that belongs to a different user and supply an arbitrary attacker-controlled `refund_address`. Because only one refund request can exist per UTXO, the attacker simultaneously blocks the legitimate owner from filing their own request. After the 14-day `unsafe_refund_timelock_sec` elapses, anyone can call `execute_refund`, which sends the victim's BTC to the attacker's address — unless DAO/Operator actively rejects the request within that window.

### Finding Description

`request_refund` is a public, permissionless entry point:

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
```

The only caller-identity check is for the optional `gas_fee` parameter (DAO/Operator only). No check verifies that `env::predecessor_account_id()` matches `deposit_msg.recipient_id` — the NEAR account that owns the deposit. [1](#0-0) 

In `request_refund_callback`, the contract verifies the Bitcoin transaction proof and that the output script matches the deposit address derived from `deposit_msg`, but again performs no check that the caller is the deposit owner: [2](#0-1) 

The `refund_address` is stored verbatim in the `RefundRequest`: [3](#0-2) 

A duplicate-request guard then blocks any subsequent `request_refund` for the same UTXO: [4](#0-3) 

`execute_refund` is also permissionless — anyone can call it after the timelock — and it pays out to the stored `refund_address`: [5](#0-4) 

The only protection is the `unsafe_refund_timelock_sec` (default 14 days), during which DAO/Operator can call `reject_refund`. Rejection is not automatic; it requires active monitoring: [6](#0-5) [7](#0-6) 

### Impact Explanation

An attacker who wins the race to call `request_refund` for a victim's unverified deposit can:
1. Redirect the entire deposit (minus gas fee) to an attacker-controlled Bitcoin address.
2. Simultaneously prevent the victim from filing a legitimate refund request for the same UTXO.

If DAO/Operator fails to reject within 14 days, the victim's BTC is permanently lost to the attacker. This matches the **Medium** impact tier: attacker-triggered potential loss of user funds gated only by an operator-dependent timelock, with no automatic on-chain enforcement.

### Likelihood Explanation

The `deposit_msg` used to derive the deposit address is emitted as a public `LogDepositAddress` event, making it trivially observable on-chain. Any unverified deposit (e.g., when a relayer is slow or offline) is a valid target. The attacker only needs to submit a transaction before the victim does and then wait 14 days. The sole mitigation — DAO/Operator rejection — is manual and not guaranteed.

### Recommendation

Restrict `request_refund` so that only `deposit_msg.recipient_id` (or a DAO/Operator) can submit a refund request for a given deposit. Concretely, add a check in `internal_request_refund` (or its callback):

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id
        || self.acl_has_role(Role::DAO.into(), env::predecessor_account_id())
        || self.acl_has_role(Role::Operator.into(), env::predecessor_account_id()),
    "Only the deposit owner or a privileged role can request a refund"
);
```

This eliminates the attack surface entirely without changing the refund flow for legitimate users.

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The event `LogDepositAddress` is emitted publicly.
2. Alice sends BTC to the returned address. The relayer is slow; `verify_deposit` has not been called yet.
3. Attacker observes the `LogDepositAddress` event, reconstructs Alice's `deposit_msg`, and calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
       refund_address = "attacker_btc_address",
       tx_bytes = <Alice's BTC tx>,
       vout = 0,
       proof = <valid inclusion proof>,
       gas_fee = None
   )
   ```
4. The call succeeds: the Light Client validates the proof, the script matches Alice's deposit address, and the `RefundRequest` is stored with `refund_address = "attacker_btc_address"`.
5. Alice attempts `request_refund` for the same UTXO — it reverts with `"Refund request already exists for this UTXO"`.
6. After 14 days, if DAO/Operator has not called `reject_refund`, the attacker calls `execute_refund(utxo_storage_key)`. The bridge constructs and MPC-signs a Bitcoin transaction paying Alice's deposit to `"attacker_btc_address"`.
7. Alice's BTC is stolen. [1](#0-0) [8](#0-7) [4](#0-3) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L132-184)
```rust
impl Contract {
    /// Submit a refund request. Verifies the BTC transaction via Light Client first.
    /// If `deposit_msg.refund_address` is set, it must match the provided `refund_address`.
    /// If `deposit_msg.refund_address` is None, the provided `refund_address` is used.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
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

**File:** contracts/satoshi-bridge/src/refund.rs (L516-526)
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
