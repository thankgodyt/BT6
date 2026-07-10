### Title
`request_refund` Callable Before Bridge Initialization Completes, Causing Permanent Loss of User's NEAR Storage Deposit - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

The bridge contract enforces a two-phase initialization: `new()` sets `chain_signatures_root_public_key = None` and `change_address = None`, and a subsequent privileged call to `sync_chain_signatures_root_public_key()` (DAO-only) populates both fields. The public `request_refund` method is callable immediately after `new()` with no guard against this uninitialized state. When a user calls it during this window, the cross-contract light-client verification succeeds, but the subsequent `request_refund_callback` panics at `generate_utxo_chain_address` because `chain_signatures_root_public_key` is `None`. The callback's state changes are rolled back, but the NEAR storage deposit attached to the original call is permanently retained by the contract with no recovery path.

### Finding Description

The constructor explicitly enforces that both critical fields are absent at init time: [1](#0-0) 

The only way to populate them is via `sync_chain_signatures_root_public_key`, which is DAO-gated and asynchronous: [2](#0-1) 

The contract is **not paused** after `new()`. The `request_refund` public entry point is decorated only with `#[pause(except(roles(Role::DAO)))]`, meaning any user can call it while the contract is unpaused: [3](#0-2) 

Inside `internal_request_refund`, the attached NEAR deposit is validated and retained by the contract, then a cross-contract call to the light client is made. The deposit is **not forwarded** to the light client: [4](#0-3) 

When the light client returns `true`, `request_refund_callback` executes and calls `generate_utxo_chain_address`: [5](#0-4) 

`generate_utxo_chain_address` → `generate_btc_public_key` → `generate_public_key`, which panics unconditionally when `chain_signatures_root_public_key` is `None`: [6](#0-5) 

The callback panic rolls back all state changes in the callback, but the NEAR deposit from the original `request_refund` call is already held in the contract's balance and is **not refunded**. There is no recovery function for stranded NEAR deposits of this kind (`claim_lost_found` handles only nBTC).

### Impact Explanation

A user who calls `request_refund` during the initialization window loses their attached NEAR storage deposit permanently. The deposit is sized to cover storage for a `RefundRequest` entry (documented as covering ~200 KB ≈ 2 NEAR in the worst case). No refund request is ever stored, no BTC funds are at risk, but the user's NEAR is irrecoverable. This is a publicly reachable panic-driven fault in a production bridge path without direct theft of bridged assets.

**Impact: Low** — matches "Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."

### Likelihood Explanation

The window exists between contract deployment and the DAO's execution of `sync_chain_signatures_root_public_key`. The light client is a separate, independently deployed contract that may already be live. Any user who discovers the bridge address and submits a valid BTC refund proof during this window triggers the bug. The window is typically short but is a real operational gap. Likelihood is **Low**.

### Recommendation

Add an explicit readiness guard at the start of `request_refund` (and any other public method that eventually calls `generate_utxo_chain_address`) to reject calls before initialization is complete:

```rust
require!(
    self.internal_config().chain_signatures_root_public_key.is_some(),
    "Bridge not yet initialized: call sync_chain_signatures_root_public_key first"
);
```

Alternatively, pause the contract in `new()` and unpause it only after `sync_root_public_key_callback` succeeds, mirroring the pattern recommended in the referenced StakingPool fix.

### Proof of Concept

1. Deploy the bridge contract; call `new(config)` — `chain_signatures_root_public_key` and `change_address` are `None`. Contract is unpaused.
2. Do **not** call `sync_chain_signatures_root_public_key`.
3. Attacker/user calls `request_refund` with a valid BTC deposit transaction and attaches the required NEAR storage deposit.
4. `internal_request_refund` passes the deposit check and dispatches a cross-contract call to the (already live) light client.
5. Light client returns `true`.
6. `request_refund_callback` is invoked; reaches `self.generate_utxo_chain_address(&path)` → `generate_public_key` → `expect("Missing chain_signatures_root_public_key")` → **panic**.
7. Callback state is rolled back; no `RefundRequest` is stored.
8. The NEAR deposit from step 3 remains in the contract with no recovery mechanism. User's NEAR is permanently lost.

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L185-191)
```rust
        require!(
            config.chain_signatures_root_public_key.is_none(),
            "Init chain_signatures_root_public_key must be None"
        );
        require!(
            config.change_address.is_none(),
            "Init change_address must be None"
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L267-277)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn sync_chain_signatures_root_public_key(&mut self) -> Promise {
        assert_one_yocto();
        require!(
            self.internal_config()
                .chain_signatures_root_public_key
                .is_none(),
            "Already sync"
        );
        self.sync_chain_signatures_root_public_key_promise()
    }
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L146-184)
```rust
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

**File:** contracts/satoshi-bridge/src/kdf.rs (L29-35)
```rust
    pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
        let mpc_pk = crypto_shared::near_public_key_to_affine_point(
            self.internal_config()
                .chain_signatures_root_public_key
                .clone()
                .expect("Missing chain_signatures_root_public_key"),
        );
```
