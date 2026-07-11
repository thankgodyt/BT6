### Title
`withdraw_rbf` Checks Caller's Capacity But Not Ownership of the Pending Withdrawal, Enabling Any User to RBF Another User's Withdrawal — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The `withdraw_rbf` function verifies the **caller's** pending-sign capacity but never confirms that the caller actually owns the pending withdrawal identified by `original_btc_pending_verify_id`. Because the function is open to any NEAR account and accepts a caller-supplied `output: Vec<TxOut>` (which encodes BTC destination addresses), an attacker can invoke it against a victim's in-flight withdrawal and supply a malicious output that redirects the BTC to the attacker's address.

### Finding Description
`withdraw_rbf` is documented as "The user actively increases the gas fee of the Withdraw transaction to accelerate it." Its implementation is:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 259-274
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();   // ← caller, not owner
    self.require_pending_sign_capacity(&account_id);  // ← checks caller's quota

    self.withdraw_rbf_chain_specific(
        account_id,                          // ← caller passed as "owner"
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
```

The function carries **no** `#[trusted_relayer]`, `#[access_control_any]`, or any other gate — it is callable by any NEAR account. [1](#0-0) 

The sibling function `cancel_withdraw`, which is restricted to `Role::DAO` or `Role::Operator`, correctly resolves the true owner before performing any capacity check:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 285-299
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id          // ← owner resolved from stored state
        .clone();
    self.require_pending_sign_capacity(&user_account_id);
    ...
}
``` [2](#0-1) 

`withdraw_rbf` performs the analogous operation but substitutes `predecessor_account_id()` for the stored owner, mirroring exactly the pattern flagged in the reference report: the caller is checked, but the actual affected party (the withdrawal owner) is not.

The `output: Vec<TxOut>` parameter is a raw Bitcoin transaction output vector. Each `TxOut` contains a `script_pubkey` that encodes the BTC destination address. Because the bridge passes this caller-supplied vector directly into `withdraw_rbf_chain_specific` — which constructs and submits a new PSBT to the MPC chain-signature pipeline — an attacker who supplies a `script_pubkey` pointing to their own BTC address can cause the bridge's MPC key to sign a transaction that sends the victim's BTC to the attacker. [3](#0-2) 

The `BTCPendingInfo` stored for every withdrawal contains the true `account_id` of the withdrawal owner: [4](#0-3) 

That stored `account_id` is never consulted in `withdraw_rbf`.

### Impact Explanation
An attacker can redirect a victim's in-flight BTC withdrawal to an attacker-controlled Bitcoin address by calling `withdraw_rbf` with a crafted `output`. The bridge's MPC signing pipeline will produce a valid signature over the attacker-supplied PSBT, resulting in permanent, irreversible loss of the victim's BTC. This matches the allowed critical impact: *"Chain-signature, PSBT, or transaction-construction failure that enables unauthorized spending or redirection of bridge-controlled funds."*

### Likelihood Explanation
- `withdraw_rbf` has no access control; any NEAR account can call it.
- Pending withdrawal IDs are emitted as on-chain events (`GenerateBtcPendingInfo`) and are publicly observable.
- The attacker needs only to observe a victim's pending ID and submit a single transaction with a malicious `output`.
- No privileged key, leaked secret, or social engineering is required.

### Recommendation
Resolve the true owner from the stored `BTCPendingInfo` before performing any capacity check or passing the account to `withdraw_rbf_chain_specific`, exactly as `cancel_withdraw` does:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    // Resolve the true owner, not the caller
    let account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    require!(
        account_id == env::predecessor_account_id(),
        "Only the withdrawal owner may submit an RBF"
    );
    self.require_pending_sign_capacity(&account_id);
    self.withdraw_rbf_chain_specific(
        account_id,
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
```

### Proof of Concept
1. Alice calls `ft_transfer_call` on the nBTC contract, transferring tokens to the bridge to initiate a withdrawal to her BTC address `alice_btc`. The bridge emits `GenerateBtcPendingInfo { account_id: "alice.near", btc_pending_id: "abc123" }`.
2. Bob (attacker) observes `btc_pending_id = "abc123"` from on-chain events.
3. Bob calls:
   ```
   withdraw_rbf(
     original_btc_pending_verify_id = "abc123",
     output = [TxOut { value: alice_amount - fee, script_pubkey: bob_btc_address }],
     chain_specific_data = None
   )
   ```
4. `withdraw_rbf` sets `account_id = bob.near`, passes it and the malicious output to `withdraw_rbf_chain_specific`.
5. The bridge constructs a new PSBT spending Alice's UTXO with Bob's `script_pubkey` as the sole output and submits it to the MPC chain-signature service.
6. The MPC service signs the PSBT; the signed transaction is broadcast to Bitcoin.
7. Alice's BTC is permanently transferred to Bob's address.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-299)
```rust
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-365)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

```
