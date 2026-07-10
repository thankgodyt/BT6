### Title
Missing Deadline on Withdrawal Initiation Allows Indefinitely Stuck User Funds - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

### Summary
The `ft_on_transfer` withdrawal path accepts a `max_gas_fee` slippage guard but no deadline parameter. Once a user initiates a withdrawal, their nBTC is immediately locked in the bridge and the resulting `BTCPendingInfo` carries a `create_time_sec` timestamp that is recorded but never enforced as an expiry. The withdrawal can remain in `PendingSign` state indefinitely with no self-service cancellation path for the user.

### Finding Description
When a user initiates a BTC withdrawal they call `ft_on_transfer` on the nBTC token contract, passing a `TokenReceiverMessage::Withdraw` payload. The struct is defined as:

```rust
Withdraw {
    target_btc_address: String,
    input: Vec<OutPoint>,
    output: Vec<TxOut>,
    max_gas_fee: Option<U128>,
    chain_specific_data: Option<ChainSpecificData>,
},
``` [1](#0-0) 

There is no `deadline` field. The bridge immediately locks the user's nBTC and removes the selected UTXOs from the available pool, then creates a `BTCPendingInfo` record:

```rust
create_time_sec: nano_to_sec(env::block_timestamp()),
last_sign_time_sec: 0,
state: PendingInfoState::WithdrawOriginal(OriginalState { ... }),
``` [2](#0-1) 

The `create_time_sec` field is stored but is never compared against any expiry in any subsequent function. The `BTCPendingInfo` struct definition confirms both timestamps exist with no enforcement logic: [3](#0-2) 

The only cancellation mechanism available is `cancel_withdraw`, which is gated behind `Role::DAO` or `Role::Operator`:

```rust
#[access_control_any(roles(Role::DAO, Role::Operator))]
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
``` [4](#0-3) 

The user has no self-service exit. The only user-callable relief valve is `withdraw_rbf` (to increase the gas fee), but this does not cancel the withdrawal or return the nBTC. [5](#0-4) 

### Impact Explanation
**Low.** A user's nBTC is locked in the bridge from the moment `ft_on_transfer` is called. If MPC signing stalls (e.g., the MPC service is congested or temporarily unavailable) or the relayer delays broadcasting, the withdrawal sits in `PendingSign` indefinitely. The user cannot recover their nBTC without DAO/Operator intervention via `cancel_withdraw`. No direct theft occurs, but the bridge enters a stuck state for that user that requires privileged operator action to resolve — matching the allowed Low impact: "stuck-state fault in production bridge/token paths without direct theft."

### Likelihood Explanation
**Low.** The stuck state requires MPC signing to be delayed or the relayer to be unresponsive. These are external dependencies. However, the design gap (no deadline, no self-service cancellation) is a structural property of every withdrawal, making the exposure permanent and cumulative across all users.

### Recommendation
1. Add an optional `deadline_sec: Option<u64>` field to `TokenReceiverMessage::Withdraw` and store it in `BTCPendingInfo`.
2. Enforce the deadline in `sign_btc_transaction`: if `env::block_timestamp() > deadline`, reject the signing attempt and allow the user to reclaim their nBTC.
3. Alternatively, expose a permissionless `cancel_withdraw_self` that any user can call on their own pending withdrawal once a configurable timeout (e.g., `create_time_sec + max_pending_sec`) has elapsed, returning the locked nBTC without requiring DAO/Operator.

### Proof of Concept
1. User calls `nbtc.ft_transfer_call(bridge_id, amount, Withdraw { target_btc_address, input, output, max_gas_fee: Some(X), chain_specific_data: None })`.
2. Bridge receives the transfer in `ft_on_transfer`, validates the PSBT, removes UTXOs, and stores `BTCPendingInfo` with `create_time_sec = now`, `state = PendingSign`.
3. MPC service becomes temporarily unavailable; `sign_btc_transaction` calls fail or are never submitted.
4. Days/weeks pass. The user's nBTC remains locked. `create_time_sec` is stale but no expiry check exists anywhere in the codebase.
5. User attempts to call `cancel_withdraw` — transaction reverts because the caller lacks `Role::DAO` or `Role::Operator`.
6. User's funds remain stuck until a privileged operator intervenes. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L11-18)
```rust
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
        chain_specific_data: Option<ChainSpecificData>,
    },
}
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L51-67)
```rust
            TokenReceiverMessage::Withdraw {
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            } => self.ft_on_transfer_withdraw_chain_specific(
                sender_id,
                amount,
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            ),
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L103-123)
```rust
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
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L107-127)
```rust
pub struct BTCPendingInfo {
    pub account_id: AccountId,
    pub btc_pending_id: String,
    #[serde(with = "u128_dec_format")]
    pub transfer_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub actual_received_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub withdraw_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub gas_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub burn_amount: u128,
    pub psbt_hex: String,
    pub vutxos: Vec<VUTXO>,
    pub signatures: Vec<Option<SignatureResponse>>,
    pub tx_bytes_with_sign: Option<Vec<u8>>,
    pub create_time_sec: u32,
    pub last_sign_time_sec: u32,
    pub state: PendingInfoState,
}
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
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
