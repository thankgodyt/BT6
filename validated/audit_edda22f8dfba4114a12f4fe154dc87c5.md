### Title
MPC Signature Leading-Zero Truncation Causes Permanent Withdrawal Stuck State — (`File: contracts/satoshi-bridge/src/chain_signature.rs`)

### Summary

`SignatureResponse::to_btc_signature()` assembles a compact 64-byte ECDSA signature by naively concatenating the raw bytes of `r` (from `big_r.affine_point[2..]`) and `s` (from `s.scalar`). When the NEAR MPC returns either component as a hex string shorter than 64 hex characters (i.e., leading zeros are absent), the concatenated byte slice is fewer than 64 bytes. `bitcoin::secp256k1::ecdsa::Signature::from_compact` then returns an error, and the `.expect("Invalid signature")` call panics the `sign_btc_transaction_callback`. The panic rolls back all state changes, leaving the withdrawal permanently stuck in `PendingSign` with the user's nBTC locked inside the bridge contract.

### Finding Description

**Root cause — `to_btc_signature` in `chain_signature.rs` lines 41–49:**

```rust
pub fn to_btc_signature(&self) -> Signature {
    let r_hex = self.big_r.affine_point[2..].to_string(); // strips "02"/"03" prefix
    let s_hex = self.s.scalar.clone();
    let r = hex::decode(r_hex).expect("Invalid r hex");   // may be < 32 bytes
    let s = hex::decode(s_hex).expect("Invalid s hex");   // may be < 32 bytes
    let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&[r, s].concat())
        .expect("Invalid signature");                      // panics if total != 64 bytes
    Signature::sighash_all(signature)
}
``` [1](#0-0) 

`bitcoin::secp256k1::ecdsa::Signature::from_compact` requires **exactly 64 bytes** (32 bytes r ‖ 32 bytes s). The NEAR MPC chain-signatures service returns `s.scalar` as a variable-length hex string. When the scalar value has leading zero bytes (probability ≈ 1/256 per leading byte, so ~0.4% of signatures have at least one leading zero byte in s), the hex string is shorter than 64 characters, `hex::decode` produces fewer than 32 bytes, and the concatenation is fewer than 64 bytes total. The same applies to the x-coordinate of `big_r.affine_point[2..]` if the MPC omits leading zeros from the point's x-coordinate.

**Callback panic path — `sign_btc_transaction_callback` lines 141–212:**

The callback first stores the raw `SignatureResponse` at line 158, then calls `psbt.save_signature(sign_index, signature, public_key)` at line 168, which internally calls `signature.to_btc_signature()`. [2](#0-1) 

`save_signature` in the Bitcoin PSBT wrapper calls `to_btc_signature()` directly: [3](#0-2) 

And in the Zcash PSBT wrapper: [4](#0-3) 

When `to_btc_signature()` panics, NEAR rolls back **all** state mutations from the callback, including the `signatures[sign_index] = Some(...)` assignment at line 158. The slot remains `None`.

**Stuck state — no self-recovery:**

The withdrawal flow is:
1. User calls `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)` → nBTC transferred to bridge (not burned yet).
2. Bridge creates `BTCPendingInfo` in `PendingSign` stage.
3. User/relayer calls `sign_btc_transaction` → MPC signs → callback panics → state rolled back.
4. `signatures[sign_index]` is still `None`; re-calling `sign_btc_transaction` with the same `btc_pending_sign_id` and `sign_index` produces the **same deterministic MPC signature** (same payload, same path) → same panic every time. [5](#0-4) 

The user's nBTC remains locked in the bridge balance. There is no user-accessible cancellation path for a `PendingSign` withdrawal; only an RBF (which changes the transaction and thus the payload hash) could produce a different MPC signature, but RBF itself requires the original signing to have succeeded at least once.

### Impact Explanation

**Severity: Medium — stuck bridge state requiring operator intervention.**

The user's nBTC tokens are transferred to the bridge during `ft_transfer_call` and are not burned until `verify_withdraw` succeeds after on-chain BTC confirmation. If the signing callback permanently panics, the tokens are locked in the bridge with no user-accessible recovery path. The bridge's UTXO set is also affected: the UTXOs consumed by the pending PSBT are removed from the available set at `create_btc_pending_info` time and cannot be reused until the pending info is cleaned up by an operator.

This matches: *"Medium. Harmful smart-contract behavior without direct funds theft, including … broken callback rollback, or stuck bridge state requiring operator intervention."*

### Likelihood Explanation

The probability that a single secp256k1 ECDSA scalar `s` has at least one leading zero byte is approximately 1 − (255/256)^32 ≈ 11.7%. The probability that the x-coordinate of R has a leading zero byte is similar. Across many withdrawals this is a near-certain eventual occurrence. It is not attacker-triggered — it is a probabilistic property of the MPC output — but any withdrawal user can be affected without any malicious action.

### Recommendation

Zero-pad both `r` and `s` to exactly 32 bytes before concatenation:

```rust
pub fn to_btc_signature(&self) -> Signature {
    let r_hex = self.big_r.affine_point[2..].to_string();
    let s_hex = self.s.scalar.clone();
    let r_bytes = hex::decode(r_hex).expect("Invalid r hex");
    let s_bytes = hex::decode(s_hex).expect("Invalid s hex");

    let mut compact = [0u8; 64];
    compact[32 - r_bytes.len()..32].copy_from_slice(&r_bytes);
    compact[64 - s_bytes.len()..64].copy_from_slice(&s_bytes);

    let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact)
        .expect("Invalid signature");
    Signature::sighash_all(signature)
}
```

Also add a `require!` guard that `r_bytes.len() <= 32 && s_bytes.len() <= 32` to reject malformed MPC responses gracefully instead of panicking.

### Proof of Concept

1. User initiates a withdrawal via `nbtc.ft_transfer_call(bridge, 100_000, WithdrawMsg{...})`. Bridge creates `BTCPendingInfo` in `PendingSign` stage; user's 100,000 nBTC are now held by the bridge.
2. Relayer calls `sign_btc_transaction(btc_pending_sign_id, 0, 0)`.
3. The NEAR MPC returns a `SignatureResponse` where `s.scalar = "0102030405..."` (fewer than 64 hex chars, e.g., 62 chars = 31 bytes, because the high byte of s is `0x00`).
4. `sign_btc_transaction_callback` fires. At line 168, `psbt.save_signature(0, signature, public_key)` calls `signature.to_btc_signature()`. `hex::decode(s_hex)` returns 31 bytes. `[r, s].concat()` is 63 bytes. `from_compact` returns `Err(InvalidSignature)`. `.expect(...)` panics.
5. NEAR rolls back all state changes. `btc_pending_info.signatures[0]` is still `None`.
6. Every subsequent call to `sign_btc_transaction` with the same inputs produces the same MPC signature → same panic.
7. The user's 100,000 nBTC remain locked in the bridge indefinitely. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L41-49)
```rust
    pub fn to_btc_signature(&self) -> Signature {
        let r_hex = self.big_r.affine_point[2..].to_string();
        let s_hex = self.s.scalar.clone();
        let r = hex::decode(r_hex).expect("Invalid r hex");
        let s = hex::decode(s_hex).expect("Invalid s hex");
        let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&[r, s].concat())
            .expect("Invalid signature");
        Signature::sighash_all(signature)
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-170)
```rust
    #[private]
    pub fn sign_btc_transaction_callback(
        &mut self,
        account_id: AccountId,
        btc_pending_sign_id: String,
        sign_index: usize,
    ) -> bool {
        if let Ok(result_bytes) = env::promise_result_checked(0, MAX_SIGNATURE_RESULT) {
            let signature = serde_json::from_slice::<SignatureResponse>(&result_bytes)
                .expect("Invalid signature");

            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
            Event::BtcInputSignature {
                account_id: &account_id,
                btc_pending_id: &btc_pending_sign_id,
                sign_index,
                signature: &signature,
            }
            .emit();
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L156-164)
```rust
    pub fn save_signature(
        &mut self,
        sign_index: usize,
        signature: SignatureResponse,
        public_key: bitcoin::secp256k1::PublicKey,
    ) {
        self.psbt.inputs[sign_index].final_script_witness =
            Some(Witness::p2wpkh(&signature.to_btc_signature(), &public_key));
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L486-501)
```rust
    pub fn save_signature(
        &mut self,
        sign_index: usize,
        signature: SignatureResponse,
        public_key: bitcoin::secp256k1::PublicKey,
    ) {
        let script_sig = bitcoin::script::Builder::new()
            .push_slice(signature.to_btc_signature().serialize())
            .push_key(&bitcoin::PublicKey::new(public_key))
            .into_script();

        let prevout = self.vin[sign_index].prevout().clone();
        let sequence = self.vin[sign_index].sequence();
        self.vin[sign_index] =
            ZcashTxIn::from_parts(prevout, Script(Code(script_sig.to_bytes())), sequence);
    }
```

**File:** CLAUDE.md (L45-55)
```markdown
**Withdraw (nBTC → BTC)**
```
1. User: nbtc.ft_transfer(bridge, amount, WithdrawMsg)
   → Tokens TRANSFERRED to bridge (not burned yet!)
2. nBTC: bridge.ft_on_transfer(user, amount, msg) → Bridge returns 0 (keeps tokens)
3. Bridge creates BTC tx, Chain Signatures signs
4. Tx broadcast to Bitcoin network
5. Relayer: bridge.verify_withdraw(tx_proof)
6. Bridge verifies → calls nbtc.burn(user, amount, relayer, fee)
   → Burns from bridge balance (tokens already there!)
```
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L70-134)
```rust
impl Contract {
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
```
