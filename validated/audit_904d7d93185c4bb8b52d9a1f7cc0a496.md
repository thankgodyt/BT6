### Title
Unchecked Arithmetic Overflow in `denormalize_amount` Permanently Freezes Bridged Funds on Inbound EVM→NEAR Transfers — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`denormalize_amount` uses a plain `*` multiplication with no overflow guard. When a user initiates a sufficiently large EVM transfer, the multiplication `amount * 10^diff_decimals` overflows `u128`. With `overflow-checks = true` (standard for NEAR contracts) the NEAR `fin_transfer_callback` panics and reverts, leaving the user's tokens permanently locked/burned on EVM with no recovery path. With `overflow-checks = false` the result silently wraps to a tiny value, so the user receives a negligible amount on NEAR while the full EVM-side value is lost.

---

### Finding Description

`denormalize_amount` at `near/omni-bridge/src/lib.rs:2776-2779`:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← no checked_mul / saturating_mul
}
``` [1](#0-0) 

This function is called unconditionally inside `fin_transfer_callback` with the amount extracted directly from the verified proof of the EVM `InitTransfer` event:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
...
fee: Self::denormalize_fee(&init_transfer.fee, decimals),
``` [2](#0-1) 

`denormalize_fee` also delegates to `denormalize_amount`:

```rust
fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
    Fee {
        fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
        ...
    }
}
``` [3](#0-2) 

The `diff_decimals` value equals `origin_decimals − decimals`, where `origin_decimals` is the NEAR-side precision (commonly 24) and `decimals` is the foreign-chain precision (e.g. 18 for ETH tokens, 6 for USDC-like tokens). For a NEAR token with 24 decimals bridged to an EVM token with 18 decimals, `diff_decimals = 6` and the overflow threshold is:

```
u128::MAX / 10^6  ≈  3.4 × 10^32  (in 18-decimal EVM units)
                  =  3.4 × 10^14  whole tokens
```

Tokens with very large supplies (e.g. meme tokens with hundreds of trillions of units in circulation) can exceed this threshold. The EVM `initTransfer` function imposes no upper bound on `amount` beyond the caller's token balance:

```solidity
function initTransfer(address tokenAddress, uint128 amount, ...) external payable {
    if (fee >= amount) { revert InvalidFee(); }
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
    ...
}
``` [4](#0-3) 

Once the EVM transaction is mined and the tokens are locked/burned, the proof is immutable. Every subsequent call to `fin_transfer_callback` with that proof will overflow and revert, with no escape hatch.

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

A user who transfers an amount exceeding the overflow threshold has their EVM-side tokens irreversibly locked or burned. The corresponding NEAR `fin_transfer_callback` will always revert (overflow panic), so the tokens can never be claimed on NEAR. There is no admin function to rescue a transfer whose proof causes an arithmetic trap. The user suffers a total, unrecoverable loss of the transferred value.

---

### Likelihood Explanation

**Low-to-medium.** The overflow threshold in whole tokens is approximately `u128::MAX / 10^origin_decimals`. For NEAR tokens with 24 decimals this is ~340 trillion whole tokens — a large but not impossible balance for tokens with very large total supplies. The condition is reachable by any unprivileged user who holds a sufficiently large balance of a supported token; no special role or key is required. The risk grows as more high-supply tokens are registered on the bridge.

---

### Recommendation

Replace the bare `*` with `checked_mul` and propagate the error explicitly:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount
        .checked_mul(10_u128.pow(diff_decimals))
        .near_expect(BridgeError::AmountOverflow)
}
```

Additionally, add a pre-flight validation in `fin_transfer_callback` that rejects proofs whose denormalized amount would exceed `u128::MAX` before any state is mutated, so the relayer receives a clean error rather than a panic.

---

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. On EVM, call `initTransfer` with `amount = u128::MAX / 10^6 + 1` (≈ 3.4 × 10^32 in 18-decimal units). The EVM transaction succeeds; tokens are locked.
3. A relayer submits the proof to NEAR `fin_transfer`.
4. Inside `fin_transfer_callback`, `denormalize_amount((u128::MAX / 10^6 + 1), decimals)` computes `(u128::MAX / 10^6 + 1) * 10^6`, which overflows `u128`.
5. With `overflow-checks = true`: the NEAR runtime traps; the transaction reverts. The proof is valid and can be re-submitted indefinitely, always reverting. The user's EVM tokens are permanently frozen.
6. With `overflow-checks = false`: the result wraps to a small value; the user receives a negligible NEAR-side balance while the full EVM-side value is lost. [1](#0-0) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L700-732)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2790-2795)
```rust
    fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
        Fee {
            fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
            native_fee: fee.native_fee,
        }
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-436)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```
