### Title
Minting Proceeds Through Unguarded Callbacks When Bridge Is Paused - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary
The `satoshi-bridge` contract applies `#[pause(except(roles(Role::DAO)))]` to all public deposit entry points, but the downstream callbacks that actually execute the nBTC mint — `verify_deposit_callback` and `verify_safe_deposit_callback` — carry no pause check. Because NEAR cross-contract calls are asynchronous, a deposit verification that was initiated just before a pause will complete and mint nBTC after the bridge is paused, bypassing the operator's intent to halt all minting.

---

### Finding Description

Every public deposit entry point is correctly gated:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs:27-47
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn verify_deposit(...) -> Promise { ... }

// contracts/satoshi-bridge/src/api/bridge.rs:72-102
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn verify_deposit_v2(...) -> Promise { ... }
``` [1](#0-0) [2](#0-1) 

Each of these dispatches a cross-contract call to the BTC light client and chains a callback. The callbacks that actually perform minting are:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs:354-384
#[private]                          // ← NO #[pause] decorator
pub fn verify_deposit_callback(...) -> PromiseOrValue<bool> {
    ...
    self.internal_mint_promise(...)  // ← mints nBTC unconditionally
    .into()
}

// contracts/satoshi-bridge/src/btc_light_client/deposit.rs:386-419
#[private]                          // ← NO #[pause] decorator
pub fn verify_safe_deposit_callback(...) -> PromiseOrValue<bool> {
    ...
    ext_nbtc::ext(...).safe_mint(recipient_id, mint_amount, msg)  // ← mints nBTC
    ...
}
``` [3](#0-2) [4](#0-3) 

`internal_mint_promise` calls `ext_nbtc::mint()` on the nBTC contract with no pause guard:

```rust
// contracts/satoshi-bridge/src/nbtc/mint.rs:19-29
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_MINT_CALL)
    .mint(recipient_id.clone(), mint_amount, ...)
``` [5](#0-4) 

The nBTC contract itself has no pause mechanism at all — `mint` only checks `assert_bridge()`:

```rust
// contracts/nbtc/src/lib.rs:126-148
pub fn mint(&mut self, ...) {
    self.assert_bridge();   // only caller check, no pause
    self.mint_inner(...);
    ...
}
``` [6](#0-5) 

---

### Impact Explanation

When the DAO pauses the bridge in response to a security incident (e.g., a compromised BTC light client returning false inclusion proofs, or a discovered vulnerability in the deposit path), any `verify_deposit` or `verify_deposit_v2` call that was already in-flight will have its callback execute in a subsequent NEAR block with no pause check. The callback will call `internal_mint_promise` → `ext_nbtc::mint()`, minting nBTC regardless of the paused state. This directly bypasses the operator's emergency control and can result in nBTC being minted against fraudulent or unintended proofs during the window the operator is trying to close.

Impact: **Medium** — bypass of bridge pause policy allowing minting to continue during a declared security incident.

---

### Likelihood Explanation

NEAR cross-contract calls are asynchronous and span multiple blocks. A `verify_deposit` call submitted one or two blocks before a pause is applied will have its callback execute after the pause takes effect. Given that deposit verification is a routine, high-frequency operation, the probability of at least one in-flight call existing at the moment of any emergency pause is high. No special attacker capability is required beyond submitting a normal deposit proof as a trusted relayer.

---

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to both `verify_deposit_callback` and `verify_safe_deposit_callback`. Since these are `#[private]` callbacks, the pause decorator will still be evaluated when the callback transaction executes, allowing the DAO to halt minting even for in-flight calls:

```rust
#[private]
#[pause(except(roles(Role::DAO)))]   // add this
pub fn verify_deposit_callback(...) -> PromiseOrValue<bool> { ... }

#[private]
#[pause(except(roles(Role::DAO)))]   // add this
pub fn verify_safe_deposit_callback(...) -> PromiseOrValue<bool> { ... }
```

Alternatively, mirror the pattern used in the Alchemix M-01 mitigation: extract the pause check into a shared helper and call it at the top of each callback before any state mutation or cross-contract mint call.

---

### Proof of Concept

1. Relayer submits `verify_deposit_v2(deposit_msg, tx_bytes, vout, proof)` — this passes the `#[pause]` gate (bridge is not yet paused) and dispatches a cross-contract call to the BTC light client. [2](#0-1) 

2. In the next block, the DAO detects a security incident and calls `pa_pause_feature("ALL")`. All `#[pause]`-gated entry points are now blocked.

3. In the same or a subsequent block, the BTC light client responds. NEAR schedules `verify_deposit_callback` as a new transaction. [3](#0-2) 

4. `verify_deposit_callback` has no `#[pause]` decorator, so it executes unconditionally. It calls `self.internal_mint_promise(...)`. [7](#0-6) 

5. `ext_nbtc::mint()` is called on the nBTC contract. The nBTC contract has no pause mechanism and only checks `assert_bridge()`, so it mints nBTC to the recipient. [6](#0-5) 

6. nBTC is minted after the bridge was paused, defeating the emergency control.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L26-47)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_deposit_v2")]
    pub fn verify_deposit(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_verify_deposit_entry(
            deposit_msg,
            tx_bytes,
            vout,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-102)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
    ) -> Promise {
        let coinbase_proof = Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof));
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L354-384)
```rust
    #[private]
    pub fn verify_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
        post_actions: Option<Vec<PostAction>>,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        self.internal_mint_promise(
            recipient_id,
            mint_amount,
            protocol_fee,
            relayer_fee,
            pending_utxo_info,
            post_actions,
        )
        .into()
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L386-419)
```rust
    #[private]
    pub fn verify_safe_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        msg: String,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );

        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L10-40)
```rust
    pub fn internal_mint_promise(
        &self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
        post_actions: Option<Vec<PostAction>>,
    ) -> Promise {
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .mint(
                recipient_id.clone(),
                mint_amount,
                protocol_fee,
                env::signer_account_id(),
                relayer_fee,
                post_actions,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .mint_callback(
                        recipient_id.clone(),
                        mint_amount,
                        protocol_fee,
                        relayer_fee,
                        pending_utxo_info,
                    ),
            )
    }
```

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```
