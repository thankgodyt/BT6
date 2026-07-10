### Title
Front-Running in `request_refund` Allows Attacker to Redirect User's BTC Refund to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `request_refund` function accepts a caller-supplied `refund_address` that is not bound to the caller's identity when `deposit_msg.refund_address` is `None`. Because the `utxo_storage_key` slot is first-come-first-served, an attacker who observes a pending `request_refund` call in the NEAR transaction pool can submit an identical call with their own BTC address before the victim's transaction is processed. The victim's call then fails with `"Refund request already exists for this UTXO"`, and the registered refund destination is the attacker's address. After the `unsafe_refund_timelock_sec` elapses, anyone can call `execute_refund` to trigger the MPC signing pipeline and send the BTC to the attacker.

### Finding Description
`request_refund` is a public, permissionless function. Its only caller-supplied inputs that affect the refund destination are `deposit_msg` and `refund_address`. When `deposit_msg.refund_address` is `None`, the function accepts any `refund_address` string from any caller without verifying that the caller is the intended beneficiary. [1](#0-0) 

The `utxo_storage_key` is derived solely from `tx_id` and `vout` — not from `refund_address` or the caller's identity: [2](#0-1) 

The callback then enforces a strict first-come-first-served rule: [3](#0-2) 

The stored `refund_address` is later used verbatim to construct the Bitcoin output that the MPC service signs: [4](#0-3) 

`execute_refund` has no access control — any account can call it after the timelock: [5](#0-4) 

**Attack path:**
1. Victim sends BTC to a deposit address derived from a `DepositMsg` with `refund_address: None`.
2. Victim submits `request_refund(deposit_msg, "victim_btc_addr", tx_bytes, vout, proof, None)`.
3. Attacker observes the pending NEAR transaction and front-runs with `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` — same `deposit_msg`, `tx_bytes`, `vout`, and `proof`, different `refund_address`.
4. Attacker's transaction lands first; `RefundRequest { refund_address: "attacker_btc_addr" }` is stored.
5. Victim's transaction reverts: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec` elapses, attacker calls `execute_refund(utxo_storage_key, None)`.
7. The PSBT is built paying `"attacker_btc_addr"`, MPC signs it, and the BTC is broadcast to the attacker.

### Impact Explanation
The victim's BTC deposit — already locked in the bridge's MPC-controlled UTXO — is redirected to the attacker's Bitcoin address. The victim loses their entire deposit. This constitutes significant loss of user funds. Even if the DAO rejects the attacker's request before `execute_refund` is called, the attacker can immediately re-front-run the victim's next `request_refund` attempt, causing indefinite DoS of the refund path and permanent locking of the victim's BTC.

### Likelihood Explanation
NEAR transaction ordering is observable before finality. The attack requires no special privilege, no leaked key, and no capital beyond the NEAR storage deposit required by `request_refund`. The attacker needs only to watch the NEAR mempool for `request_refund` calls and resubmit with a higher gas priority. The `deposit_msg`, `tx_bytes`, `vout`, and `proof` are all visible in the victim's pending transaction. The attack is cheap and repeatable.

### Recommendation
Bind the refund destination to data that cannot be substituted by a third party. Two options:

1. **Require `deposit_msg.refund_address` to be set at deposit time.** Make `refund_address` mandatory in `DepositMsg` so it is committed to the deposit address derivation path (via `get_deposit_path`) before any BTC is sent. The `request_refund` function already enforces that the supplied `refund_address` matches `deposit_msg.refund_address` when the field is present; making it mandatory eliminates the free-form path entirely.

2. **Restrict `request_refund` to the `deposit_msg.recipient_id`.** If the free-form `refund_address` path must be kept, require `env::predecessor_account_id() == deposit_msg.recipient_id` so only the intended NEAR recipient can register a refund request for their own deposit.

### Proof of Concept
```
// Victim's pending NEAR transaction (visible in mempool):
request_refund(
  deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
  refund_address = "bc1qvictim...",
  tx_bytes = <victim's BTC tx>,
  vout = 0,
  proof = <valid merkle proof>,
  gas_fee = None
)

// Attacker front-runs with identical inputs except refund_address:
request_refund(
  deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
  refund_address = "bc1qattacker...",   // <-- attacker's address
  tx_bytes = <same BTC tx>,
  vout = 0,
  proof = <same merkle proof>,
  gas_fee = None
)

// Attacker's tx lands first → RefundRequest stored with refund_address = "bc1qattacker..."
// Victim's tx reverts: "Refund request already exists for this UTXO"

// After unsafe_refund_timelock_sec:
execute_refund(utxo_storage_key = "<txid>@0", chain_specific_data = None)
// → PSBT built paying bc1qattacker..., MPC signs, BTC sent to attacker
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L529-532)
```rust
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-30)
```rust
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
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
