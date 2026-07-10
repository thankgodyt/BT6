The code confirms the off-by-one. Here is the full analysis:

**Constants:**
- `GAS_FOR_FT_TRANSFER_CALL = Gas::from_tgas(30)` [1](#0-0) 
- `MIN_PER_POST_ACTIONS_GAS = Gas::from_tgas(30)` [2](#0-1) 

**Bridge-side guard** uses strict `<`, so `gas == 30 Tgas` passes: [3](#0-2) 

**nBTC-side guard** uses strict `>`, so `prepaid_gas == 30 Tgas` panics: [4](#0-3) 

**Dispatch** passes the user-supplied gas verbatim via `.with_static_gas(gas)`, so `handle_post_action` receives exactly 30 Tgas: [5](#0-4) 

The promise is `.detach()`-ed, so the panic is silent and unobservable to the caller. [6](#0-5) 

---

### Title
Off-by-one between bridge gas floor and nBTC gas guard silently drops post_action DeFi calls — (`contracts/nbtc/src/lib.rs`)

### Summary
`MIN_PER_POST_ACTIONS_GAS` and `GAS_FOR_FT_TRANSFER_CALL` are both 30 Tgas, but the bridge rejects `gas < 30` (allowing `==`) while `handle_post_action` requires `prepaid_gas > 30` (rejecting `==`). A depositor who supplies exactly 30 Tgas passes bridge validation, but the resulting detached promise panics, silently dropping the DeFi action.

### Finding Description
In `deposit_msg.rs`, the per-post-action gas floor check is:
```rust
if gas.as_gas() < MIN_PER_POST_ACTIONS_GAS.as_gas() { return None; }
```
This allows `gas == 30 Tgas`. The value is then forwarded unchanged via `.with_static_gas(gas)` when scheduling the detached `handle_post_action` call. Inside `handle_post_action`, the guard is:
```rust
require!(env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL, "More gas is required");
```
`30 Tgas > 30 Tgas` is `false`, so the `require!` panics. Because the promise is detached, the panic is silent — no callback, no refund, no error propagation.

### Impact Explanation
The nBTC is already minted to the depositor before `handle_post_actions` runs, so funds are not lost. However, the depositor's intended DeFi action (e.g., deposit into a lending protocol) is silently dropped with no on-chain indication of failure visible to the depositor at submission time. This violates the invariant that a `post_action` accepted by bridge-side validation will execute in the nBTC contract.

### Likelihood Explanation
Any unprivileged depositor can trigger this by setting `post_action.gas = 30_000_000_000_000` in their deposit message. The value is the exact minimum the bridge accepts, making it a natural boundary value a user or integrator might choose. No special access is required.

### Recommendation
Align the two bounds. Either:
- Change the bridge floor check to `gas.as_gas() <= MIN_PER_POST_ACTIONS_GAS.as_gas()` (reject `==`), or
- Change the nBTC guard to `env::prepaid_gas() >= GAS_FOR_FT_TRANSFER_CALL`.

The former is safer: reject `gas == 30 Tgas` at the bridge so the invariant "accepted gas values always satisfy the nBTC guard" holds.

### Proof of Concept
1. Submit a BTC deposit with `deposit_msg` containing `post_actions: [{ receiver_id: "some.defi", amount: "1", msg: "", gas: 30000000000000 }]`.
2. Bridge-side `check_deposit_msg` passes (30 Tgas is not `< 30 Tgas`).
3. nBTC is minted; `handle_post_actions` schedules `handle_post_action` with `.with_static_gas(Gas::from_tgas(30))`.
4. `handle_post_action` executes with `prepaid_gas() == 30 Tgas`; `require!(30 > 30)` panics with `"More gas is required"`.
5. The detached promise failure is silent; the DeFi action is never executed.

### Citations

**File:** contracts/nbtc/src/lib.rs (L32-32)
```rust
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(30);
```

**File:** contracts/nbtc/src/lib.rs (L371-375)
```rust
            if let Some(gas) = gas {
                Self::ext(env::current_account_id())
                    .with_static_gas(gas)
                    .handle_post_action(sender_id.clone(), receiver_id, amount, memo, msg)
                    .detach();
```

**File:** contracts/nbtc/src/lib.rs (L393-396)
```rust
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L8-8)
```rust
const MIN_PER_POST_ACTIONS_GAS: Gas = Gas::from_tgas(30);
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L157-165)
```rust
                if gas.as_gas() < MIN_PER_POST_ACTIONS_GAS.as_gas() {
                    Event::InvalidPostAction {
                        index: Some(index),
                        err_msg: format!(
                            "The gas amount({gas}) does not meet the minimum requirement of {MIN_PER_POST_ACTIONS_GAS}."
                        ),
                    }
                    .emit();
                    return None;
```
