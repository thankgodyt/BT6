### Title
Unprivileged Caller Can Hijack Refund Destination for Any Deposit Lacking a Pre-authorized Refund Address — (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` is callable by any NEAR account with no check that the caller is the original depositor (`deposit_msg.recipient_id`). When a deposit was made with `deposit_msg.refund_address = None`, the caller of `request_refund` freely supplies the `refund_address` field. An attacker who observes a pending, unfinalized deposit can submit a refund request pointing to their own BTC address, and after the 14-day `unsafe_refund_timelock_sec` elapses, execute the refund and permanently redirect the deposited BTC to themselves.

### Finding Description
`request_refund` is a public, permissionless entry point: [1](#0-0) 

The only privileged check inside the function is for the optional `gas_fee` parameter; the core refund-request creation path (`internal_request_refund`) is reached by any caller: [2](#0-1) 

The `DepositMsg` struct contains an optional `refund_address` field: [3](#0-2) 

When `deposit_msg.refund_address` is `None`, the `refund_address` argument supplied by the caller of `request_refund` is used as the BTC destination. There is no verification that the caller is `deposit_msg.recipient_id` or any other authorized party. The `deposit_msg` itself (including its hash, which determines the deposit address) is publicly observable via the `LogDepositAddress` event emitted by `get_user_deposit_address`: [4](#0-3) 

The two distinct refund timelocks are configured in `Config`: [5](#0-4) 

The `unsafe_refund_timelock_sec` (default 14 days) applies precisely to the case where `deposit_msg.refund_address` was `None` — i.e., the attacker-controlled path. [6](#0-5) 

### Impact Explanation
If an attacker successfully registers a refund request before the legitimate user does (or before the relayer finalizes the deposit), and the deposit is never finalized via `verify_deposit`, the attacker calls `execute_refund` after 14 days and the bridge's MPC pipeline sends the deposited BTC to the attacker's address. The original depositor loses their BTC permanently with no recourse. This constitutes a significant, permanent loss of user funds.

### Likelihood Explanation
The attack is realistic under the following conditions, all of which are observable on-chain:
- The user deposits BTC with `deposit_msg.refund_address = None` (a common pattern for standard deposits).
- The relayer is temporarily unavailable, slow, or the deposit falls below `min_deposit_amount` and is never finalized.
- The attacker monitors the BTC chain and NEAR events for new deposits, reconstructs the `deposit_msg` from the emitted `LogDepositAddress` event, and submits `request_refund` with their own BTC address before the legitimate user does.

No privileged access, leaked keys, or third-party compromise is required. The attacker only needs to be a standard NEAR account and pay the anti-spam storage deposit.

### Recommendation
Add a caller-identity check inside `request_refund` (or `internal_request_refund`) that requires `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, when `deposit_msg.refund_address` is `None`, derive and store the refund address only from the `recipient_id`'s registered BTC withdrawal address, or require the caller to prove ownership of the NEAR account that initiated the deposit. A DAO/Operator bypass for the caller check can be retained for operational recovery.

### Proof of Concept
1. Alice deposits 0.01 BTC to the bridge address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The `LogDepositAddress` event is emitted on NEAR with the full `deposit_msg`.
2. The relayer goes offline before calling `verify_deposit`.
3. Attacker Bob observes the event, reconstructs `deposit_msg`, and calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
     refund_address = "bob_btc_address",
     tx_bytes = <Alice's BTC tx>,
     vout = 0,
     proof = <valid Light Client proof>,
     gas_fee = None
   )
   ```
   with the required NEAR storage deposit attached.
4. The refund request is stored with `refund_address = "bob_btc_address"`.
5. After 14 days (`unsafe_refund_timelock_sec`), Bob calls `execute_refund(utxo_storage_key, None)`.
6. The bridge constructs and MPC-signs a BTC transaction sending Alice's 0.01 BTC to Bob's address. Alice's funds are permanently lost.

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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/config.rs (L114-118)
```rust
    // Timelock for refunds where `deposit_msg.refund_address` is pre-authorized.
    pub refund_timelock_sec: u64,
    // Timelock for refunds where the refund address comes from the request caller
    // (`deposit_msg.refund_address` was None). Must be >= `refund_timelock_sec`.
    pub unsafe_refund_timelock_sec: u64,
```
