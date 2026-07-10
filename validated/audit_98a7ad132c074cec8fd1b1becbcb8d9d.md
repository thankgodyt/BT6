The code confirms this is a real vulnerability. Here is the complete analysis:

---

### Title
Off-by-one gas boundary allows bridge-validated `post_action` to panic in `handle_post_action` — (`contracts/nbtc/src/lib.rs`)

### Summary

An off-by-one between the bridge-side gas floor check (`<`, exclusive) and the nBTC-side gas guard (`>`, exclusive) means a `post_action` with `gas = 30 Tgas` passes bridge validation but always panics inside `handle_post_action`, silently dropping the depositor's intended DeFi action.

### Finding Description

Two constants are both set to exactly 30 Tgas:

- `MIN_PER_POST_ACTIONS_GAS = Gas::from_tgas(30)` in the bridge validator [1](#0-0) 
- `GAS_FOR_FT_TRANSFER_CALL = Gas::from_tgas(30)` in the nBTC contract [2](#0-1) 

The bridge-side check uses a **strict less-than** (`<`), so `gas == 30 Tgas` is accepted:

```rust
if gas.as_gas() < MIN_PER_POST_ACTIONS_GAS.as_gas() { return None; }
``` [3](#0-2) 

The nBTC-side guard uses a **strict greater-than** (`>`), so `prepaid_gas == 30 Tgas` panics:

```rust
require!(
    env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
    "More gas is required"
);
``` [4](#0-3) 

`handle_post_actions` schedules the detached promise with exactly the user-supplied gas via `.with_static_gas(gas)`:

```rust
Self::ext(env::current_account_id())
    .with_static_gas(gas)
    .handle_post_action(...)
    .detach();
``` [5](#0-4) 

So `env::prepaid_gas()` inside `handle_post_action` equals exactly the user-supplied value. At 30 Tgas, `30 > 30` is `false` and the `require!` panics before `internal_transfer` executes.

### Impact Explanation

The panic fires **before** `internal_transfer`, so the nBTC (already minted to `sender_id` in the main flow) is not forwarded to the DeFi `receiver_id`. The depositor's funds are not permanently lost — they remain in the nBTC contract under `sender_id` — but the intended DeFi action is silently dropped with no on-chain error surfaced to the user. This violates the bridge invariant that a `post_action` passing bridge-side validation will execute successfully in the nBTC contract.

### Likelihood Explanation

Any depositor who specifies `gas = 30_000_000_000_000` (the documented minimum) hits this. The minimum is the natural default a user or SDK would choose. The path is fully public and requires no privilege.

### Recommendation

Make the two boundaries consistent. Either:
- Change the bridge floor check to `<=` (reject `gas < MIN` becomes reject `gas <= MIN`, i.e. require `gas > 30 Tgas`), **or**
- Change the nBTC guard to `>=` (`require!(prepaid_gas >= GAS_FOR_FT_TRANSFER_CALL)`).

The simplest fix is to raise `MIN_PER_POST_ACTIONS_GAS` to 31 Tgas, or change the `require!` to `>=`.

### Proof of Concept

1. Submit a BTC deposit with `post_actions: [{ receiver_id: "some.defi", amount: X, msg: "...", gas: 30000000000000 }]`.
2. Bridge-side `check_deposit_msg` passes: `30 Tgas < 30 Tgas` is `false`, so no rejection.
3. `handle_post_actions` schedules `handle_post_action` with `.with_static_gas(Gas::from_tgas(30))`.
4. `handle_post_action` executes; `env::prepaid_gas() == 30 Tgas`; `require!(30 > 30)` panics with `"More gas is required"`.
5. The detached promise fails silently; the DeFi transfer is never executed.

### Citations

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
