### Title
Unauthenticated `request_refund` Allows Any Caller to Front-Run and Redirect User BTC Refunds to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

`request_refund` is callable by any NEAR account and accepts a caller-supplied `refund_address` without verifying the caller is the original depositor. Because only one refund request can exist per UTXO, an attacker who observes a deposit on-chain can front-run the legitimate user, register their own BTC address as the refund destination, and permanently block the user from submitting a competing request. After `unsafe_refund_timelock_sec` elapses without DAO intervention, anyone can call `execute_refund` and the bridge MPC-signs a transaction sending the user's BTC to the attacker.

### Finding Description

`request_refund` sits in a `#[trusted_relayer]` impl block but carries no method-level `#[trusted_relayer]` attribute, making it callable by any NEAR account. [1](#0-0) 

Inside `internal_request_refund`, when `deposit_msg.refund_address` is `None` (the common case for users who did not pre-specify a refund address), the caller-supplied `refund_address` is accepted without any ownership check: [2](#0-1) 

The callback enforces that the output script matches the deposit address derived from `deposit_msg`, but it does **not** verify that the caller owns the NEAR account in `deposit_msg.recipient_id` or has any relationship to the deposit: [3](#0-2) 

A hard uniqueness constraint then blocks any subsequent `request_refund` for the same UTXO: [4](#0-3) 

The `deposit_msg` is public: `get_user_deposit_address` emits it as an on-chain event, and relayers publish it when calling `verify_deposit_v2`. An attacker can reconstruct it from chain history. [5](#0-4) 

After `unsafe_refund_timelock_sec` passes, `execute_refund` is also permissionless and will MPC-sign a transaction paying the attacker's address: [6](#0-5) 

The `unsafe_refund_timelock_sec` path is taken precisely because the refund address was supplied by the caller rather than embedded in `deposit_msg`: [7](#0-6) 

### Impact Explanation

An attacker who successfully front-runs `request_refund` causes the bridge's MPC service to sign a Bitcoin transaction that sends the depositor's BTC to the attacker's address. The legitimate user permanently loses their BTC: they cannot submit a competing refund request (blocked by the uniqueness check), and `verify_deposit` will also be blocked once `execute_refund` marks the UTXO as verified. This is a direct, complete theft of user funds — Critical impact. [8](#0-7) 

### Likelihood Explanation

The `deposit_msg` is public on-chain (emitted by `get_user_deposit_address` and visible in relayer call arguments). The attacker only needs to pay the non-refundable NEAR anti-spam deposit (a small fixed cost) to redirect arbitrarily large BTC amounts. The attack window is the entire period between the BTC deposit confirming and the legitimate user calling `request_refund` — which can be hours or days if the user is waiting for a relayer failure to become apparent. The DAO mitigation (`unsafe_refund_timelock_sec`) requires active monitoring and timely rejection; if the DAO misses the window, the theft is irreversible. [9](#0-8) 

### Recommendation

Add an ownership check in `request_refund`: require that `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. This ensures only the intended NEAR recipient (or a pre-authorized BTC address embedded in `deposit_msg`) can register a refund destination, eliminating the front-running surface entirely. Alternatively, allow multiple competing refund requests per UTXO and require DAO approval before any is executed. [10](#0-9) 

### Proof of Concept

```
1. Alice deposits 1 BTC with deposit_msg = {recipient_id: "alice.near", refund_address: None}.
   The bridge emits LogDepositAddress event containing the full deposit_msg JSON.

2. The relayer fails to call verify_deposit_v2 (e.g., network issue).
   Alice's BTC sits in the bridge deposit address, unfinalized.

3. Attacker observes the LogDepositAddress event on-chain, extracts deposit_msg.

4. Attacker calls request_refund(
       deposit_msg = <alice's deposit_msg>,
       refund_address = "attacker_btc_address",
       tx_bytes = <alice's deposit tx, also public on Bitcoin>,
       vout = 0,
       proof = <valid merkle proof, also public>,
       gas_fee = None
   ) with the required NEAR anti-spam deposit attached.

5. request_refund_callback verifies:
   - Light client confirms tx inclusion ✓
   - output.script_pubkey matches deposit address derived from deposit_msg ✓
   - No existing refund request for this UTXO ✓
   → Stores RefundRequest{refund_address: "attacker_btc_address"}.

6. Alice tries to call request_refund with her own BTC address.
   → Panics: "Refund request already exists for this UTXO". Alice is blocked.

7. After unsafe_refund_timelock_sec elapses (DAO does not reject):
   Attacker calls execute_refund(utxo_storage_key).
   Bridge builds a PSBT paying "attacker_btc_address" and requests MPC signature.

8. sign_btc_transaction is called; MPC signs the transaction.
   Attacker broadcasts it. Alice's 1 BTC is sent to the attacker.
``` [11](#0-10)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-510)
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

**File:** contracts/satoshi-bridge/src/refund.rs (L146-153)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
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

**File:** contracts/satoshi-bridge/src/refund.rs (L222-228)
```rust
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

```

**File:** contracts/satoshi-bridge/src/refund.rs (L497-548)
```rust
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L12-28)
```rust
pub struct DepositMsg {
    // The NEAR account receiving nBTC.
    pub recipient_id: AccountId,
    // Parameters for executing ft_transfer_call after successful nBTC minting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    // Used to support other dApps extending based on verify_deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    // Replacment for the legacy post_actions to support safer cross-contract calls.
    // If this field is present, the legacy post_actions field must be None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
    // BTC address for refund if deposit is never finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
