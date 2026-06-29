### Title
Unchecked u128 Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary
`denormalize_amount` performs an unchecked `u128` multiplication. When a user initiates a transfer on EVM with an amount large enough that `amount × 10^(origin_decimals − decimals)` exceeds `u128::MAX`, the NEAR `fin_transfer_callback` panics under `overflow-checks = true`. Because the EVM tokens are already locked/burned before the NEAR callback executes, the panic permanently freezes the user's bridged funds with no recovery path.

### Finding Description
`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

There is no overflow guard on the multiplication. The function is called inside `fin_transfer_callback` immediately after the EVM proof is accepted:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [2](#0-1) 

It is also called in `fast_fin_transfer` and `claim_fee_callback`: [3](#0-2) [4](#0-3) 

The EVM `initTransfer` accepts `uint128 amount` with no upper-bound restriction beyond the type itself: [5](#0-4) 

The workspace has `overflow-checks = true` (noted in CLAUDE.md), so the multiplication panics rather than wrapping silently: [6](#0-5) 

The CLAUDE.md false-positive note addresses only the *underflow* case (`origin_decimals < decimals`). The *overflow* case — where a valid, correctly-configured token pair is used but the transferred amount is too large — is not covered by that note and has a materially different consequence: the EVM tokens are already irrevocably locked/burned before the NEAR callback runs.

### Impact Explanation
When `fin_transfer_callback` panics:
- The EVM `initTransfer` transaction has already executed; tokens are locked or burned in the EVM contract.
- The NEAR callback failure does not revert the EVM state.
- No NEAR-side finalization record is written, so the proof could theoretically be re-submitted, but `denormalize_amount` will panic again with the same amount — there is no recovery path.
- The user's bridged funds are permanently frozen.

This matches the **Critical** impact category: *permanent freezing of bridged funds*.

### Likelihood Explanation
The overflow threshold for a token with `diff_decimals = d` is `amount > u128::MAX / 10^d`. For `d = 6` (e.g., a NEAR token with 24 decimals bridged to an EVM token normalized to 18 decimals), the threshold is ≈ 3.4 × 10³² in raw EVM token units. For `d = 18` the threshold drops to ≈ 3.4 × 10²⁰. While these are large numbers, the EVM contract imposes no ceiling below `uint128` max, and tokens with very large supplies (high-supply meme tokens, wrapped assets) can reach these values. Any user who sends an amount above the threshold — even accidentally — permanently loses their funds with no on-chain warning.

### Recommendation
Add a checked multiplication in `denormalize_amount` and propagate the error to the caller:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount.checked_mul(10_u128.pow(diff_decimals))
}
```

All call sites (`fin_transfer_callback`, `fast_fin_transfer`, `claim_fee_callback`, `denormalize_fee`) should handle `None` by panicking with a descriptive error **before** any EVM-side state change is considered irreversible — or, better, enforce a maximum transferable amount on the EVM side that guarantees the denormalized value fits in `u128`.

### Proof of Concept
1. Deploy a NEAR token with `origin_decimals = 24`; the EVM counterpart is normalized to `decimals = 18` (`diff_decimals = 6`).
2. Call `initTransfer` on the EVM contract with `amount = u128::MAX / 10^6 + 1` (≈ 3.4 × 10³² + 1). Tokens are locked in the EVM contract.
3. A relayer submits the proof to NEAR `fin_transfer`.
4. `fin_transfer_callback` calls `denormalize_amount(amount, decimals)`, which evaluates `(u128::MAX/10^6 + 1) * 10^6 > u128::MAX`.
5. With `overflow-checks = true`, the NEAR runtime panics; the callback transaction fails.
6. The EVM tokens remain permanently locked; no NEAR tokens are minted; no recovery function exists. [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L698-732)
```rust
    #[private]
    #[payable]
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

**File:** near/omni-bridge/src/lib.rs (L770-772)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
```

**File:** near/omni-bridge/src/lib.rs (L1122-1127)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
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
    }
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
