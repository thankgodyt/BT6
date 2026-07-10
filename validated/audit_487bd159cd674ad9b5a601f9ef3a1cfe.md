### Title
Pause Mechanism Blocks All Recovery Paths for In-Flight Bridge Operations, Causing Temporary Locking of User Funds - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `satoshi-bridge` contract applies `#[pause(except(roles(Role::DAO)))]` to every critical bridge function, including both the deposit completion path (`verify_deposit_v2`) and the only user-accessible recovery path (`request_refund`). If the contract is paused while a deposit is in-flight — BTC already sent to the deposit address on Bitcoin, nBTC not yet minted — the user has zero recovery options until the contract is unpaused. The same pause simultaneously blocks the withdrawal signing path and the user-accessible cancel path, leaving nBTC stuck in the bridge requiring privileged operator intervention.

---

### Finding Description

The contract is decorated with `Pausable` from `near_plugins`: [1](#0-0) 

Every user-facing and relayer-facing function in the bridge flow carries `#[pause(except(roles(Role::DAO)))]`:

**Deposit completion** — `verify_deposit_v2`: [2](#0-1) 

**User refund request** — `request_refund`: [3](#0-2) 

**Refund execution** — `execute_refund`: [4](#0-3) 

**Lost-found claim** — `claim_lost_found`: [5](#0-4) 

**Withdrawal initiation** — `ft_on_transfer`: [6](#0-5) 

**MPC signing** — `sign_btc_transaction`: [7](#0-6) 

**Deposit scenario (direct analog):**

1. User sends BTC to the deposit address derived from their NEAR account — irreversible on Bitcoin.
2. The contract is paused (legitimate security response, e.g., to halt an ongoing exploit).
3. The relayer attempts `verify_deposit_v2` → reverts: contract is paused. nBTC is never minted.
4. The user attempts `request_refund` to recover their BTC → also reverts: contract is paused.
5. The user's BTC is locked in the deposit address with no on-chain recovery path available while the pause is active.

**Withdrawal scenario:**

1. User calls `ft_transfer_call` on the nBTC token → `ft_on_transfer` succeeds (contract not yet paused). nBTC is transferred to the bridge.
2. Contract is paused before `sign_btc_transaction` is called.
3. The MPC signing step cannot proceed — `sign_btc_transaction` is paused. The BTC transaction is never broadcast.
4. The user cannot call `withdraw_rbf` (paused).
5. `cancel_withdraw` is restricted to `Role::DAO` or `Role::Operator`: [8](#0-7) 

6. The user's nBTC is stuck in the bridge, requiring privileged operator intervention to cancel and route funds to `lost_found`.
7. Even after the operator cancels, `claim_lost_found` is also paused, adding a second blocked step: [9](#0-8) 

---

### Impact Explanation

**Deposit path:** User's BTC is locked in the deposit address with no user-accessible recovery mechanism while the contract is paused. Both the minting path and the refund path are simultaneously blocked. This constitutes temporary locking of bridged funds with no user-side remedy.

**Withdrawal path:** User's nBTC is held by the bridge contract with no user-accessible cancellation path. Recovery requires privileged operator action (`cancel_withdraw`) followed by another privileged-bypass call (`claim_lost_found`), constituting a stuck bridge state requiring operator intervention.

**Impact:** Medium — temporary locking of user BTC/nBTC; stuck bridge state requiring operator intervention; no direct theft but funds are inaccessible to the user for the duration of the pause.

---

### Likelihood Explanation

**Likelihood:** Low. The pause must coincide with an in-flight bridge operation. However, pauses are most likely to be triggered precisely during active exploit scenarios, which are also the periods of highest bridge activity. The combination is realistic in a security-incident response.

---

### Recommendation

Exempt `request_refund` from the pause guard so users retain a recovery path for their locked BTC even when the contract is paused. Similarly, consider exempting `claim_lost_found` so users can retrieve nBTC already credited to them. The signing and verification paths may legitimately remain paused, but the user-side recovery paths should not be blocked simultaneously with the deposit/withdrawal paths.

---

### Proof of Concept

1. User sends 0.5 BTC to their deposit address on Bitcoin (transaction confirmed, irreversible).
2. DAO calls `pa_pause_feature` to pause the contract in response to an unrelated exploit.
3. Relayer calls `verify_deposit_v2(deposit_msg, tx_bytes, vout, proof)` → panics: `"Contract is paused"`.
4. User calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, None)` → panics: `"Contract is paused"`.
5. User's 0.5 BTC remains locked in the deposit address. No user-callable function can recover it until the DAO unpauses the contract. [10](#0-9) [11](#0-10)

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-285)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-451)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-583)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L20-23)
```rust
#[near]
impl FungibleTokenReceiver for Contract {
    #[pause(except(roles(Role::DAO)))]
    fn ft_on_transfer(
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-22)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-67)
```rust
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
```
