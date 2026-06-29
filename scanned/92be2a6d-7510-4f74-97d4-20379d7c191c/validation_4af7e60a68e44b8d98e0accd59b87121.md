### Title
Missing Empty Recipient Validation in `initTransfer` Allows Permanent Freezing of Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.initTransfer` and `initTransfer1155` accept an empty `recipient` string with no validation. Any unprivileged user can call either function with `recipient = ""`, causing their tokens to be irreversibly burned or locked on the EVM side while the cross-chain transfer can never be completed on NEAR, resulting in permanent loss of bridged funds.

### Finding Description
The `initTransfer` function in `OmniBridge.sol` validates only that `fee >= amount` (reverting with `InvalidFee`) and that `msg.value` covers the native fee. It performs no check that the `recipient` string is non-empty or syntactically valid as an `OmniAddress`. [1](#0-0) 

The same omission exists in `initTransfer1155`: [2](#0-1) 

When `recipient = ""` is supplied:
1. The `fee >= amount` guard does not fire (e.g., `amount=100, fee=0`).
2. Tokens are burned (bridge token path) or transferred into escrow (native token path) — both irreversible on-chain.
3. An `InitTransfer` event is emitted with an empty `recipient` field.
4. The NEAR relayer picks up the event and submits a proof. The NEAR bridge attempts to parse the recipient string as an `OmniAddress`. An empty string matches no valid `OmniAddress` variant and the proof submission panics/fails.
5. No recovery path exists: the nonce is consumed, the tokens are gone, and the transfer can never be finalized.

By contrast, the Starknet bridge explicitly guards against zero amounts (`assert(amount > 0, 'ERR_ZERO_AMOUNT')`), but neither the EVM nor the Starknet bridge validates the recipient string: [3](#0-2) 

The NEAR-side `OmniAddress` parsing that would reject an empty string is only reached after the EVM-side state mutation has already committed: [4](#0-3) 

### Impact Explanation
Any user who calls `initTransfer` or `initTransfer1155` with an empty `recipient` string permanently loses their bridged tokens. The EVM-side burn/lock is irreversible, and the NEAR side cannot finalize a transfer with an unparseable recipient. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation
The function is publicly callable by any token holder without any role or permission. A user could trigger this accidentally (e.g., a frontend bug, a direct contract call with a missing field, or a programmatic integration that omits the recipient). The `fee >= amount` guard does not protect against this path.

### Recommendation
Add an explicit non-empty recipient check at the top of both `initTransfer` and `initTransfer1155`, before any state mutation occurs:

```solidity
if (bytes(recipient).length == 0) revert InvalidRecipient();
```

Optionally, enforce a minimum structural check (e.g., presence of a `:` separator matching the `chain:address` format) to catch other malformed inputs early.

### Proof of Concept
1. Deploy `OmniBridge` with a registered bridge token.
2. Approve the bridge to spend `100` tokens.
3. Call:
   ```solidity
   OmniBridge.initTransfer(
       bridgeTokenAddress,
       100,   // amount
       0,     // fee
       0,     // nativeFee
       "",    // recipient — empty string, no validation
       ""     // message
   );
   ```
4. The call succeeds: `BridgeToken.burn(msg.sender, 100)` executes, `currentOriginNonce` increments, and `InitTransfer` is emitted with `recipient = ""`.
5. The NEAR relayer submits the proof. The bridge contract attempts `OmniAddress::from_str("")` (or equivalent parsing), which fails. The transfer is permanently stuck and the 100 tokens are lost. [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-451)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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
```

**File:** starknet/src/omni_bridge.cairo (L290-293)
```text
            assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

            assert(amount > 0, 'ERR_ZERO_AMOUNT');
            assert(fee < amount, 'ERR_INVALID_FEE');
```

**File:** near/omni-types/src/lib.rs (L275-296)
```rust
    pub fn encode(&self, separator: char, skip_zero_address: bool) -> String {
        let (chain_str, address) = match self {
            Self::Eth(address) => ("eth", address.to_string()),
            Self::Near(address) => ("near", address.to_string()),
            Self::Sol(address) => ("sol", address.to_string()),
            Self::Arb(address) => ("arb", address.to_string()),
            Self::Base(address) => ("base", address.to_string()),
            Self::Bnb(address) => ("bnb", address.to_string()),
            Self::Pol(address) => ("pol", address.to_string()),
            Self::HyperEvm(address) => ("hlevm", address.to_string()),
            Self::Btc(address) => ("btc", address.clone()),
            Self::Zcash(address) => ("zcash", address.clone()),
            Self::Strk(address) => ("strk", address.to_string()),
            Self::Abs(address) => ("abs", address.to_string()),
            Self::Fogo(address) => ("fogo", address.to_string()),
        };

        if skip_zero_address && self.is_zero() {
            chain_str.to_string()
        } else {
            format!("{chain_str}{separator}{address}")
        }
```
