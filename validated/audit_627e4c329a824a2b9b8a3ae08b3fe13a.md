### Title
`OmniToken::mint()` with `msg` Permanently Broken Due to Conflicting `assert_one_yocto` Requirement Inside `ft_transfer_call` — (`File: near/omni-token/src/lib.rs`)

### Summary

`OmniToken::mint()` has a code path (when `msg` is `Some(...)`) that internally calls `self.ft_transfer_call()`. The `ft_transfer_call` implementation delegates to `near_contract_standards::FungibleToken::ft_transfer_call`, which unconditionally calls `assert_one_yocto()`. However, the bridge contract always invokes `mint()` with zero attached deposit. This makes every cross-chain transfer that carries a non-empty `msg` field permanently fail on the NEAR side, analogous to the M-01 double-`nonReentrant` deadlock.

### Finding Description

`OmniToken::mint()` branches on whether `msg` is `Some`: [1](#0-0) 

When `msg` is `Some(...)`, it first deposits tokens to `env::predecessor_account_id()` (the bridge contract), then calls `self.ft_transfer_call(account_id, amount, None, msg)`: [2](#0-1) 

`OmniToken::ft_transfer_call` delegates directly to `self.token.ft_transfer_call(...)`, which is `near_contract_standards::FungibleToken::ft_transfer_call`. Per the NEP-141 standard, that function calls `assert_one_yocto()` unconditionally, requiring exactly 1 yoctoNEAR to be attached.

The bridge contract defines the gas constant for the `mint` cross-contract call and issues it with **no attached deposit**: [3](#0-2) 

The `ext_token` trait declaration confirms the bridge calls `mint` with no deposit builder: [4](#0-3) 

The execution chain is:

```
bridge calls mint(account_id, amount, Some(msg))  [0 yoctoNEAR attached]
  → OmniToken::mint()  [#[payable], 0 yocto received]
    → self.ft_transfer_call(account_id, amount, None, msg)
      → self.token.ft_transfer_call(...)
        → assert_one_yocto()  ← PANICS, 0 ≠ 1 yocto
```

The panic causes the cross-contract call to fail. Because `internal_deposit` already ran before the panic, the token supply on the NEAR side is incremented but the transfer to the recipient never completes, leaving the minted balance stranded in the bridge contract's account on the token contract.

### Impact Explanation

Any cross-chain transfer whose `msg` field is non-empty (used for DeFi integrations, atomic swaps, or protocol-level callbacks) will always revert at the `mint` step. The source-chain tokens have already been locked or burned. If the bridge's `fin_transfer_callback` does not explicitly detect and refund a failed `mint` call, those funds are permanently frozen — matching the "permanent freezing of bridged funds" Critical impact class.

### Likelihood Explanation

The `msg` field is a first-class feature of the bridge protocol, exposed through `InitTransferMsg` and propagated through `TransferMessage` all the way to `fin_transfer_callback`. Any user or protocol that initiates a cross-chain transfer with a non-empty `msg` (e.g., to trigger a DeFi action on NEAR upon receipt) will trigger this path. No special privilege is required; any bridge user can reach it.

### Recommendation

Either:

1. Attach `ONE_YOCTO` when the bridge calls `mint()` with a non-`None` `msg`:
   ```rust
   ext_token::ext(token_id.clone())
       .with_static_gas(MINT_TOKEN_GAS)
       .with_attached_deposit(ONE_YOCTO)   // add this
       .mint(account_id, amount, msg)
   ```

2. Or remove the `assert_one_yocto()` guard from the internal call path inside `OmniToken::mint()` by bypassing `ft_transfer_call` and instead calling the underlying promise-building logic directly, since the controller-only `assert_controller()` check already provides the necessary authorization.

### Proof of Concept

1. User initiates a cross-chain transfer (e.g., EVM → NEAR) with `msg = "some_defi_action"`.
2. Bridge finalizes the transfer on NEAR via `fin_transfer_callback`, which calls `send_tokens` → `ext_token::mint(recipient, amount, Some("some_defi_action"))` with 0 yoctoNEAR attached.
3. Inside `OmniToken::mint()`, the `Some(msg)` branch runs: `internal_deposit` credits the bridge contract, then `self.ft_transfer_call(...)` is called.
4. `FungibleToken::ft_transfer_call` calls `assert_one_yocto()` → **panics**.
5. The cross-contract call fails. The bridge contract now holds a token balance it cannot forward. The source-chain funds remain locked/burned with no corresponding release on NEAR. [5](#0-4) [2](#0-1) [3](#0-2)

### Citations

**File:** near/omni-token/src/lib.rs (L126-144)
```rust
    #[payable]
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** near/omni-token/src/lib.rs (L209-218)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L73-73)
```rust
const MINT_TOKEN_GAS: Gas = Gas::from_tgas(5);
```

**File:** near/omni-bridge/src/lib.rs (L158-158)
```rust
    fn mint(&mut self, account_id: AccountId, amount: U128, msg: Option<String>);
```
