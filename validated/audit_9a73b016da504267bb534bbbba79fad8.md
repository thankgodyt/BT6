### Title
nBTC Tokens Remain Freely Transferable When the Bridge Is Paused, Enabling Sale of Non-Withdrawable Tokens — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `satoshi-bridge` contract applies `#[pause]` guards to every critical operation (deposit, withdrawal, refund, lost-found claim). The `nbtc` token contract, however, has **no pause mechanism at all**. `ft_transfer` and `ft_transfer_call` are unconditionally callable by any account regardless of the bridge's pause state, allowing nBTC holders to freely sell or transfer tokens that cannot currently be withdrawn.

---

### Finding Description

The `satoshi-bridge` contract derives `Pausable` from `near-plugins` and gates every state-mutating bridge function behind `#[pause(except(roles(Role::DAO)))]`:

- `verify_deposit_v2` — minting blocked when paused [1](#0-0) 
- `ft_on_transfer` — withdrawal initiation blocked when paused [2](#0-1) 
- `verify_withdraw_v2` — burn blocked when paused [3](#0-2) 
- `execute_refund` — refund execution blocked when paused [4](#0-3) 
- `claim_lost_found` — lost-fund recovery blocked when paused [5](#0-4) 

The `nbtc` token contract, by contrast, implements `FungibleTokenCore` with no pause guard on either transfer entry point:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // no pause check
    ...
    self.token.ft_transfer(receiver_id, amount, memo);
}

fn ft_transfer_call(...) -> PromiseOrValue<U128> {
    // no pause check
    self.token.ft_transfer_call(receiver_id, amount, memo, msg)
}
``` [6](#0-5) 

The `nbtc` contract also contains a legacy "Near Intents" withdrawal path inside `ft_transfer`: when `receiver_id == env::current_account_id()` and the memo starts with `"WITHDRAW_TO:"`, tokens are silently redirected to the configured `withdraw_relayer_address` — again with no pause check. [7](#0-6) 

---

### Impact Explanation

When the bridge is paused:

1. No new nBTC can be minted (deposit path blocked).
2. No nBTC can be burned / withdrawn (withdrawal and verify paths blocked).
3. No refunds can be executed (refund path blocked).
4. Users with nBTC in their own accounts can **still freely transfer or sell** those tokens via `ft_transfer` / `ft_transfer_call` on the nbtc contract.

A holder of nBTC can sell tokens to a DEX pool or a counterparty that does not inspect the bridge's pause state. The buyer receives nBTC that cannot be redeemed for BTC for the duration of the pause. If the pause is extended or the bridge is deprecated without a migration path, the tokens become permanently non-withdrawable while remaining freely tradeable — a direct analog to the expired-option scenario in the reference report.

This is a **Low** impact finding: a publicly reachable invariant-violation in production bridge/token paths without direct theft of funds.

---

### Likelihood Explanation

The `PauseManager` role is granted to the deployer at initialization and can be granted to additional accounts by DAO. [8](#0-7) 

Any pause event (security incident, upgrade, emergency) immediately creates the asymmetry: bridge operations halt, but nBTC transfers do not. Any nBTC holder — including one who knows the bridge is paused — can immediately exploit this window by selling tokens on a secondary market. No special privilege is required; a standard NEAR account with an nBTC balance is sufficient.

---

### Recommendation

1. **Add a pause guard to the nbtc token contract.** Integrate `near-plugins`' `Pausable` trait into `contracts/nbtc/src/lib.rs` and annotate `ft_transfer` and `ft_transfer_call` with `#[pause]`, mirroring the bridge contract's pattern. Ensure that transfers *back to the bridge* (e.g., for withdrawal initiation) are exempted so the withdrawal flow can still be unwound by DAO even during a pause.

2. **Alternatively, document the asymmetry explicitly.** If free transferability during a pause is intentional, add prominent documentation warning integrators (DEXes, aggregators) to check the bridge's pause state before accepting nBTC deposits.

---

### Proof of Concept

```
1. PauseManager calls `pa_pause_feature("ALL")` on satoshi-bridge.
   → verify_deposit_v2, ft_on_transfer, verify_withdraw_v2, execute_refund,
     claim_lost_found all revert for non-DAO callers.

2. Alice holds 1 nBTC in her NEAR account.

3. Alice calls nbtc.ft_transfer(dex.near, 1_nbtc, None).
   → No pause check exists; transfer succeeds unconditionally.
   → DEX pool now holds 1 nBTC.

4. Bob buys 1 nBTC from the DEX pool, expecting to withdraw BTC.

5. Bob calls nbtc.ft_transfer_call(satoshi-bridge, 1_nbtc, None, Withdraw{...}).
   → ft_on_transfer on satoshi-bridge panics: "Contract is paused".
   → ft_resolve_transfer returns tokens to Bob — withdrawal fails.

6. Bob is stuck holding nBTC he cannot redeem for BTC for the duration
   of the pause, having paid market price for a non-withdrawable token.
```

The root cause is the absence of any pause guard in `contracts/nbtc/src/lib.rs` on `ft_transfer` (line 183) and `ft_transfer_call` (line 199), while all redemption paths in `contracts/satoshi-bridge/src/api/bridge.rs` and `contracts/satoshi-bridge/src/api/token_receiver.rs` are fully paused. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L72-73)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L241-242)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-450)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-582)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L22-23)
```rust
    #[pause(except(roles(Role::DAO)))]
    fn ft_on_transfer(
```

**File:** contracts/nbtc/src/lib.rs (L182-207)
```rust
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L222-222)
```rust
        contract.acl_grant_role(Role::PauseManager.into(), env::predecessor_account_id());
```
