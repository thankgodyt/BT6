### Title
Any User Can Bypass Deposit Fees via the `safe_deposit` Path in `verify_deposit_v2` - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`verify_deposit_v2` routes to a completely fee-free deposit path whenever `deposit_msg.safe_deposit.is_some()`, with no restriction on who may set that field. Any user can craft a `DepositMsg` containing `safe_deposit: Some(SafeDepositMsg { msg: "" })`, send BTC to the resulting address, and call `verify_deposit_v2` themselves to receive the full deposited amount as nBTC — paying zero deposit fee.

### Finding Description

The bridge exposes two distinct deposit paths inside `verify_deposit_v2`:

```
if deposit_msg.safe_deposit.is_some() {
    self.internal_safe_verify_deposit_entry(...)   // ← NO fee deducted
} else {
    self.internal_verify_deposit_entry(...)         // ← deposit_fee deducted
}
```

**Standard path** (`internal_verify_deposit`): [1](#0-0) 

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);
```

`mint_amount = deposit_amount − deposit_fee` is minted; protocol and relayer fees are collected.

**Safe path** (`internal_safe_verify_deposit`): [2](#0-1) 

```rust
promise.then(
    Self::ext(env::current_account_id())
        .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
        .verify_safe_deposit_callback(
            recipient_id,
            deposit_amount.into(),   // ← full amount, no fee subtracted
            deposit_msg.msg,
            pending_utxo_info,
        ),
)
```

`verify_safe_deposit_callback` then calls `safe_mint(recipient_id, mint_amount /* = full deposit_amount */, msg)`: [3](#0-2) 

The `safe_mint_callback` emits `protocol_fee: U128(0)` and `relayer_fee: U128(0)` — no fee accounting whatsoever: [4](#0-3) 

The routing decision in `verify_deposit_v2` is made purely on `deposit_msg.safe_deposit.is_some()`: [5](#0-4) 

There is no caller-identity check, no role guard, and no whitelist that restricts who may supply `safe_deposit: Some(...)`. The `#[trusted_relayer]` attribute on the `impl` block is a logging/tracking decorator — not an access-control gate — as confirmed by the fact that `request_refund` (in the same block) is openly callable by any NEAR account: [6](#0-5) 

The `DepositMsg` struct exposes `safe_deposit` as a plain optional field that any caller may populate: [7](#0-6) 

The deposit address is derived from the SHA-256 hash of the serialised `DepositMsg`: [8](#0-7) 

So a user who includes `safe_deposit: Some(...)` gets a unique deposit address tied to that message, sends BTC there, and then calls `verify_deposit_v2` with the same message — the bridge accepts the proof and mints the full amount with zero fee.

### Impact Explanation

Every deposit that goes through the safe path skips `deposit_bridge_fee`, which is split into `protocol_fee` (credited to `cur_available_protocol_fee`) and `relayer_fee`. For large deposits the fee can be substantial. The protocol permanently loses those fees; the user receives `deposit_fee` worth of extra nBTC. This is a direct, repeatable bypass of the bridge's fee policy.

### Likelihood Explanation

The `DepositMsg` struct and the `safe_deposit` field are part of the public JSON API. Any user who inspects the contract interface or reads the source can discover the field. No special privilege, leaked key, or operator cooperation is required — only a valid BTC transaction to the derived address and the small NEAR storage deposit that `verify_deposit_v2` requires when `safe_deposit` is set.

### Recommendation

Restrict the safe-deposit path to authorised callers. Options include:

1. Add a role check inside `verify_deposit_v2` (or `internal_safe_verify_deposit_entry`) that requires the caller to hold a designated role (e.g. `Role::OmniBridge`) before the `safe_deposit` branch is taken.
2. Alternatively, split `verify_deposit_v2` into two separate entry points — one for standard deposits (public) and one for safe/integration deposits (role-gated) — so the routing cannot be influenced by user-supplied message fields.

### Proof of Concept

```
1. Attacker constructs:
   deposit_msg = DepositMsg {
       recipient_id: attacker.near,
       safe_deposit: Some(SafeDepositMsg { msg: "" }),
       post_actions: None,
       extra_msg: None,
       refund_address: None,
   }

2. Attacker calls get_user_deposit_address(deposit_msg)
   → receives a unique BTC address derived from hash(deposit_msg)

3. Attacker sends, e.g., 1 BTC to that address.

4. After confirmation, attacker calls:
   verify_deposit_v2(deposit_msg, tx_bytes, vout, proof)
   with attached NEAR ≥ required_balance_for_safe_deposit()

5. Bridge checks deposit_msg.safe_deposit.is_some() == true
   → routes to internal_safe_verify_deposit_entry
   → verify_safe_deposit_callback mints deposit_amount (full 1 BTC in satoshis) to attacker
   → protocol_fee = 0, relayer_fee = 0

6. With the standard path the attacker would have received
   deposit_amount − deposit_bridge_fee.get_fee(deposit_amount).
   The difference is the stolen protocol + relayer fee.
```

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L52-56)
```rust
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
            let (protocol_fee, relayer_fee) = config
                .deposit_bridge_fee
                .get_protocol_and_relayer_fee(deposit_fee);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L104-113)
```rust
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_safe_deposit_callback(
                        recipient_id,
                        deposit_amount.into(),
                        deposit_msg.msg,
                        pending_utxo_info,
                    ),
            )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L409-412)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L458-465)
```rust
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee: U128(0),
            relayer_account_id: env::signer_account_id(),
            relayer_fee: U128(0),
            success: is_success,
        }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L81-101)
```rust
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```
