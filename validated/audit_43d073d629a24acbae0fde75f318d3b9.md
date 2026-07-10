### Title
Unprivileged Caller Can Redirect Victim's Unfinalized BTC Deposit Refund to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

`request_refund` accepts a caller-supplied `refund_address` without verifying that the caller is the rightful owner of the deposit (i.e., `deposit_msg.recipient_id`). Because `deposit_msg` is publicly logged on-chain via `get_user_deposit_address`, an attacker can front-run or independently submit a refund request for any victim's unfinalized BTC deposit, directing the BTC to the attacker's own address.

---

### Finding Description

`request_refund` is a public, permissionless function:

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
``` [1](#0-0) 

Inside `internal_request_refund`, the only validation of `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — users typically do not pre-authorize a refund address), **any caller may supply any BTC address as `refund_address`** with no check that `env::predecessor_account_id() == deposit_msg.recipient_id`.

The `deposit_msg` is not secret. When a user calls `get_user_deposit_address`, the full `deposit_msg` is emitted in a public on-chain event:

```rust
Event::LogDepositAddress {
    deposit_msg,
    path,
    deposit_address: deposit_address.clone(),
}
.emit();
``` [3](#0-2) 

The BTC transaction itself is also public on-chain, so `tx_bytes` and the Merkle `proof` are trivially obtainable by anyone.

After the refund request is stored, `execute_refund` is also permissionless:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
``` [4](#0-3) 

Once the `unsafe_refund_timelock_sec` elapses, anyone can call `execute_refund` to trigger the MPC signing pipeline and send the BTC to the attacker's address.

The longer `unsafe_refund_timelock_sec` is the only mitigation — it gives DAO/Operator time to call `reject_refund`. This is an operational control, not a code-level access control fix, and it fails if the DAO/Operator does not monitor all incoming refund requests. [5](#0-4) 

---

### Impact Explanation

**Critical.** An attacker can permanently steal BTC from any user whose deposit was never finalized (e.g., due to relayer failure, network congestion, or a deliberate front-run of `verify_deposit`). The BTC is sent via MPC signing to the attacker's Bitcoin address and is irrecoverable. This constitutes significant theft of user funds.

---

### Likelihood Explanation

**Medium-High.** The `deposit_msg` is publicly logged on-chain via `get_user_deposit_address`. The BTC transaction and Merkle proof are publicly available on the Bitcoin blockchain. The attacker only needs to:
1. Watch for `LogDepositAddress` events.
2. Monitor the Bitcoin chain for the corresponding deposit.
3. Watch for any `verify_deposit` call — if none arrives within a reasonable window, submit `request_refund` with their own BTC address.

No privileged access, leaked keys, or social engineering is required. The attack is fully executable by any unprivileged NEAR account.

---

### Recommendation

Add a caller-identity check in `request_refund`. When `deposit_msg.refund_address` is `None`, require that `env::predecessor_account_id() == deposit_msg.recipient_id`:

```rust
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
) -> Promise {
    // If no pre-authorized refund address, only the deposit recipient may request a refund.
    if deposit_msg.refund_address.is_none() {
        require!(
            env::predecessor_account_id() == deposit_msg.recipient_id,
            "Only the deposit recipient may request a refund without a pre-authorized refund_address"
        );
    }
    ...
}
```

Alternatively, require `deposit_msg.refund_address` to always be set at deposit time (enforced in `get_user_deposit_address`), so the refund destination is always pre-authorized and immutable.

---

### Proof of Concept

1. Victim calls `get_user_deposit_address(deposit_msg = {recipient_id: "victim.near", refund_address: None})`. The full `deposit_msg` is emitted in a `LogDepositAddress` event.
2. Victim sends BTC to the returned deposit address. The BTC transaction is confirmed on-chain.
3. The relayer does not call `verify_deposit` (failure, delay, or attacker front-runs it).
4. Attacker reads `deposit_msg` from the `LogDepositAddress` event and fetches `tx_bytes` + Merkle proof from the Bitcoin network.
5. Attacker calls:
   ```
   request_refund(
     deposit_msg = {recipient_id: "victim.near", refund_address: None},
     refund_address = "attacker_btc_address",
     tx_bytes = <victim's deposit tx>,
     vout = <victim's output index>,
     proof = <valid Merkle proof>,
     gas_fee = None
   )
   ```
   No check prevents this — `deposit_msg.refund_address` is `None`, so the caller-supplied `refund_address` is accepted unconditionally.
6. After `unsafe_refund_timelock_sec` elapses (assuming DAO/Operator does not reject), attacker calls `execute_refund(utxo_storage_key)`.
7. The bridge's MPC pipeline signs a Bitcoin transaction sending the victim's BTC to `attacker_btc_address`. The victim's BTC is permanently stolen. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
```rust
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
