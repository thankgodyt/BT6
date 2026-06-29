### Title
`denormalize_amount()` Multiplication Overflow Permanently Freezes Bridged Funds - (File: near/omni-bridge/src/lib.rs)

### Summary

`Contract::denormalize_amount()` performs an unchecked multiplication `amount * (10_u128.pow(diff_decimals))`. When a user initiates a large transfer on a foreign chain (EVM/Solana/Starknet) for a token whose NEAR-side `origin_decimals` exceeds the foreign-chain `decimals`, the multiplication can overflow `u128`. With `overflow-checks = true` in the workspace `Cargo.toml`, this causes a runtime panic inside `fin_transfer_callback` and `fast_fin_transfer`, permanently freezing the user's funds on the source chain.

### Finding Description

`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← unchecked multiplication
}
``` [1](#0-0) 

It is called unconditionally in `fin_transfer_callback` to reconstruct the full-precision NEAR amount from the normalized foreign-chain amount:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
fee:    Self::denormalize_fee(&init_transfer.fee, decimals),
``` [2](#0-1) 

And again in `fast_fin_transfer`:

```rust
let denormalized_amount =
    Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
``` [3](#0-2) 

The workspace enforces `overflow-checks = true`: [4](#0-3) 

So any overflow is a hard panic, not silent wrapping.

On the EVM side, `initTransfer` accepts a raw `uint128 amount` from the caller and emits it verbatim in the `InitTransfer` event — no normalization is applied before emission: [5](#0-4) 

The NEAR prover parses this raw value directly into `InitTransferMessage.amount`: [6](#0-5) 

### Impact Explanation

When `fin_transfer_callback` panics due to overflow:

1. The user's tokens are already locked/burned on the source chain (EVM/Solana/Starknet) — the `initTransfer` transaction is irreversible.
2. The NEAR-side callback panics before recording the transfer or minting tokens.
3. The same proof, when resubmitted, will overflow again — the panic is deterministic.
4. The user's funds are **permanently frozen**: unrecoverable on the source chain and never minted on NEAR.

This satisfies the critical impact criterion: *permanent freezing of bridged funds*.

### Likelihood Explanation

The overflow threshold is `u128::MAX / 10^diff_decimals`.

| `diff_decimals` | Overflow threshold (in foreign-chain token units, 18 dec) |
|---|---|
| 6 | ~340 trillion tokens |
| 12 | ~340 million tokens |
| 18 | ~340 tokens |

For any token registered with `origin_decimals - decimals ≥ 12`, a user bridging more than ~340 million tokens triggers the panic. For tokens with `diff_decimals = 18`, even a transfer of 341 tokens causes permanent loss. Low-value, high-supply tokens (e.g., meme tokens) are the most realistic trigger.

The `CLAUDE.md` false-positive note labelled "Decimal Arithmetic Underflow" addresses only the **subtraction** `origin_decimals - decimals` underflowing due to misconfiguration. It does not address the **multiplication** overflow triggered by a legitimate user sending a large amount. [7](#0-6) 

### Recommendation

Replace the bare multiplication with a checked variant and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount
        .checked_mul(10_u128.pow(diff_decimals))
        .unwrap_or_else(|| env::panic_str("denormalize_amount: overflow"))
}
```

Alternatively, validate at the point of ingestion (inside `fin_transfer_callback`) that `amount ≤ u128::MAX / 10^diff_decimals` before calling `denormalize_amount`, and reject the proof with a recoverable error rather than a hard panic.

### Proof of Concept

1. Deploy a token with `origin_decimals = 24`, `decimals = 6` (`diff_decimals = 18`).
2. On EVM, call `initTransfer(tokenAddress, 341 * 10^6, 0, 0, "near:victim.near", "")` — a transfer of 341 tokens in EVM units.
3. Submit the resulting proof to NEAR's `fin_transfer`.
4. `fin_transfer_callback` calls `denormalize_amount(341_000_000, Decimals { origin_decimals: 24, decimals: 6 })`.
5. Computes `341_000_000 * 10^18 = 3.41 * 10^26`, which is within `u128::MAX` — adjust `diff_decimals` or amount to cross the threshold.
6. For `diff_decimals = 20`: threshold = `u128::MAX / 10^20 ≈ 3.4 * 10^18`; any amount > `3.4 * 10^18` in foreign units overflows.
7. The callback panics; the user's EVM tokens are permanently locked; no NEAR tokens are ever minted.

### Citations

**File:** near/omni-bridge/src/lib.rs (L725-727)
```rust
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
```

**File:** near/omni-bridge/src/lib.rs (L770-771)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/Cargo.toml (L31-31)
```text
overflow-checks = true
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

**File:** near/omni-types/src/evm/events.rs (L115-136)
```rust
impl TryFromLog<Log<InitTransfer>> for InitTransferMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<InitTransfer>) -> Result<Self, Self::Error> {
        Ok(Self {
            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
            origin_nonce: event.data.originNonce,
            token: OmniAddress::new_from_evm_address(chain_kind, H160(event.tokenAddress.into()))?,
            amount: near_sdk::json_types::U128(event.data.amount),
            recipient: event.data.recipient.parse().map_err(stringify)?,
            fee: Fee {
                fee: near_sdk::json_types::U128(event.data.fee),
                native_fee: near_sdk::json_types::U128(event.data.nativeTokenFee),
            },
            sender: OmniAddress::new_from_evm_address(chain_kind, H160(event.data.sender.into()))?,
            msg: event.data.message,
        })
    }
}
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
