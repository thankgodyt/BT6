### Title
Missing Token Registration Validation in `init_transfer` Allows Permanent Locking of User Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function in the NEAR `omni-bridge` contract accepts any NEP-141 token via `ft_on_transfer` without validating that the token is registered in the bridge's token registry. Tokens from unregistered contracts are accepted and stored in `pending_transfers`, but the transfer can never be executed because `sign_transfer` will panic when it cannot resolve the token address. There is no cancel or refund path, so the user's tokens are permanently locked in the bridge.

---

### Finding Description

`ft_on_transfer` is a public entry point callable by any NEP-141 token contract. It dispatches to `init_transfer` using `env::predecessor_account_id()` as the `token_id`: [1](#0-0) 

Inside `init_transfer`, the only validations performed are:

1. The recipient chain is not NEAR.
2. The fee is strictly less than the amount. [2](#0-1) 

There is **no check** that `token_id` exists in `token_id_to_address` (the bridge's token registry). The transfer message is constructed and stored unconditionally, with the bridge retaining all transferred tokens (return value `U128(0)`).

Later, when a relayer calls `sign_transfer`, the bridge attempts to resolve the token's foreign-chain address: [3](#0-2) 

`get_token_address` performs a lookup in `token_id_to_address`: [4](#0-3) 

For an unregistered token this returns `None`, causing `sign_transfer` to panic with `FailedToGetTokenAddress`. The transfer remains in `pending_transfers` indefinitely with no user-accessible cancellation path.

---

### Impact Explanation

A user who sends an unregistered NEP-141 token to the bridge via `ft_transfer_call` will have their tokens permanently locked inside the bridge contract. The transfer record is stored but can never progress to signing or finalization. No refund or cancel mechanism is visible in the contract. This constitutes permanent freezing of user funds, matching the critical impact tier: *"loss or permanent freezing of bridged funds."*

---

### Likelihood Explanation

The attack surface is fully user-reachable with no privilege required. Any account can call `ft_transfer_call` on any NEP-141 token pointing at the bridge. Realistic scenarios include:

- A user bridges a token before the DAO has registered it.
- A user mistypes the token account ID.
- A token is delisted/unregistered after a transfer is initiated.

The `ft_on_transfer` entry point is public and unpermissioned (aside from the global pause), making accidental or deliberate triggering straightforward.

---

### Recommendation

Add a registration check at the top of `init_transfer` before incrementing the nonce or storing any state:

```rust
require!(
    self.token_id_to_address
        .get(&(init_transfer_msg.get_destination_chain(), token_id.clone()))
        .is_some(),
    BridgeError::TokenNotRegistered.as_ref()
);
```

Because `ft_on_transfer` must return the number of tokens to refund, a failed validation that returns the full `amount` will cause the token contract to refund the user automatically — no separate cancel path is needed if the check is placed before any state mutation.

---

### Proof of Concept

1. Deploy any NEP-141-compliant token contract `unregistered.token.near` that is **not** present in `token_id_to_address` on the bridge.
2. Call `ft_transfer_call` on `unregistered.token.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"recipient\": \"Eth:0xDEAD...\", \"fee\": \"0\", \"native_token_fee\": \"0\"}"
   }
   ```
3. `ft_on_transfer` is invoked on the bridge; `init_transfer` runs, increments `current_origin_nonce`, and stores the `TransferMessage` in `pending_transfers`. The bridge returns `U128(0)`, keeping all 1 000 000 tokens.
4. Call `sign_transfer` with the resulting `transfer_id`. The call panics at `get_token_address` → `FailedToGetTokenAddress` because `token_id_to_address` has no entry for `(Eth, unregistered.token.near)`.
5. The transfer is permanently stuck. The 1 000 000 tokens are irrecoverable by the user. [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-263)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
```

**File:** near/omni-bridge/src/lib.rs (L462-485)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1360-1366)
```rust
    pub fn get_token_address(
        &self,
        chain_kind: ChainKind,
        token: AccountId,
    ) -> Option<OmniAddress> {
        self.token_id_to_address.get(&(chain_kind, token))
    }
```
