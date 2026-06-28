### Title
Missing Token Burn in `resolve_utxo_fin_transfer` Causes Token Supply Inflation — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`resolve_utxo_fin_transfer` omits the `burn_tokens_if_needed` call that its structural counterpart `resolve_fast_transfer` performs. When the UTXO-chain token is a deployed bridge token, the bridge mints new tokens to the recipient **and** permanently retains the tokens sent by the UTXO connector, inflating the on-chain supply by the full transfer amount on every successful UTXO → NEAR finalization.

### Finding Description

The UTXO fin-transfer-to-NEAR flow is:

```
utxo_fin_transfer
  └─ utxo_fin_transfer_to_near
       └─ utxo_fin_transfer_to_near_callback   (receives tokens from connector via ft_transfer_call)
            └─ send_tokens  →  mint(recipient, amount)   (for deployed tokens)
                 └─ resolve_utxo_fin_transfer            (callback)
```

`utxo_fin_transfer_to_near_callback` calls `send_tokens`, which for a deployed bridge token calls `mint`, creating `amount` new tokens and crediting them to the recipient. [1](#0-0) 

After `send_tokens` resolves, `resolve_utxo_fin_transfer` is invoked. In the success branch it only emits a log and returns `U128(0)`: [2](#0-1) 

There is **no call to `burn_tokens_if_needed`**. The `amount` of tokens that the UTXO connector transferred to the bridge via `ft_transfer_call` remain in the bridge's balance, permanently unburned.

Compare with the structurally identical fast-transfer callback, which explicitly burns the tokens the relayer deposited, with the comment *"Burn the tokens to ensure the locked tokens are not double-minted"*: [3](#0-2) 

`burn_tokens_if_needed` withdraws from the bridge's own balance via the token's `burn` entry-point: [4](#0-3) 

The `burn` function on `OmniToken` withdraws from `predecessor_account_id` (the bridge contract): [5](#0-4) 

For the UTXO token to be a deployed token, `deploy_native_token` must have been called for the chain (e.g., BTC/ZEC). This is the standard deployment path: [6](#0-5) 

### Impact Explanation

Every successful UTXO → NEAR finalization where the UTXO token is a deployed bridge token inflates the circulating supply by `amount`. The bridge accumulates a growing balance of tokens that were never burned. This constitutes **escrow/token-supply mis-accounting**: the bridge holds tokens that represent unbacked supply, breaking the 1:1 peg between locked UTXO-chain assets and NEAR-side tokens. An attacker who can trigger repeated UTXO fin transfers (or observe the accumulated balance) can exploit the inflated supply to extract value beyond what was legitimately bridged.

### Likelihood Explanation

The UTXO connector is a trusted contract, but the bug is triggered by **normal bridge usage** — any user who sends BTC/ZEC on the origin chain causes the connector to call `ft_transfer_call` on the bridge. No special privilege is required. The bug fires on every successful UTXO → NEAR transfer where the token is deployed, making it continuously exploitable at scale.

### Recommendation

Add `self.burn_tokens_if_needed(token_id.clone(), amount)` in the success branch of `resolve_utxo_fin_transfer`, mirroring `resolve_fast_transfer`:

```rust
pub fn resolve_utxo_fin_transfer(...) -> U128 {
    let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
    // Burn the tokens received from the connector to prevent supply inflation
    self.burn_tokens_if_needed(token_id.clone(), amount);
    if Self::is_refund_required(is_ft_transfer_call) {
        self.remove_fin_utxo_transfer(...);
        amount
    } else {
        env::log_str(...);
        U128(0)
    }
}
```

### Proof of Concept

1. Admin calls `deploy_native_token(ChainKind::Btc, "Bitcoin", "BTC", 8)` — BTC token is inserted into `deployed_tokens`.
2. Admin calls `add_utxo_chain_connector(ChainKind::Btc, connector_id, btc_token_id, 8)`.
3. User sends 1 BTC on Bitcoin. Connector calls `ft_transfer_call(bridge, 100_000_000, ..., UtxoFinTransfer{recipient: Near("alice")})`.
4. Bridge receives 100_000_000 satoshi-units of BTC token.
5. `utxo_fin_transfer_to_near_callback` → `send_tokens` → `mint(alice, 100_000_000)` — 100_000_000 new tokens minted to Alice.
6. `resolve_utxo_fin_transfer` returns `U128(0)` — connector's tokens are consumed; bridge holds 100_000_000 BTC tokens that are never burned.
7. Total BTC token supply is now inflated by 100_000_000 per transfer. Repeating this N times inflates supply by N × amount, unbacked by any locked BTC.

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L994-1011)
```rust
        self.send_tokens(
            token_id.clone(),
            recipient,
            amount,
            &utxo_fin_transfer_msg.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_UTXO_FIN_TRANSFER_GAS)
                .resolve_utxo_fin_transfer(
                    token_id,
                    amount,
                    utxo_fin_transfer_msg,
                    origin_chain,
                    storage_owner,
                ),
        )
        .into()
```

**File:** near/omni-bridge/src/lib.rs (L1016-1044)
```rust
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1200-1221)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn deploy_native_token(
        &mut self,
        chain_kind: ChainKind,
        name: String,
        symbol: String,
        decimals: u8,
    ) -> Promise {
        let native_token_address = get_native_token_address(chain_kind)
            .near_expect(BridgeError::FailedToGetNativeTokenAddress);
        self.deploy_token_internal(
            chain_kind,
            &native_token_address,
            BasicMetadata {
                name,
                symbol,
                decimals,
            },
            env::attached_deposit(),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
```

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```
