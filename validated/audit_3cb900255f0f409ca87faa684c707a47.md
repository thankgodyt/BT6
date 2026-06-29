### Title
Missing `recipient` Validation in `OmniBridge.initTransfer()` Enables Permanent Freezing of Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer()` and `OmniBridge.initTransfer1155()` accept a `recipient` string parameter that is never validated for emptiness or structural correctness. An unprivileged user who supplies an empty `recipient` string causes tokens to be irreversibly burned or locked on the EVM side while the corresponding NEAR-side finalization permanently fails, with no on-chain recovery path.

---

### Finding Description

`initTransfer` performs only one input guard — `fee >= amount` — before burning or locking the caller's tokens and emitting `InitTransfer`:

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    uint128 fee,
    uint128 nativeFee,
    string calldata recipient,   // ← never validated
    string calldata message
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    if (fee >= amount) {
        revert InvalidFee();
    }
    // tokens burned/locked here …
    emit BridgeTypes.InitTransfer(
        msg.sender, tokenAddress, currentOriginNonce,
        amount, fee, nativeFee,
        recipient,   // ← emitted verbatim, even if ""
        message
    );
}
``` [1](#0-0) 

The same omission exists in `initTransfer1155`: [2](#0-1) 

The NEAR hub's `fin_transfer_callback` expects the recipient encoded as a valid `OmniAddress` (format `"chain:address"`). An empty string cannot be deserialized into any `OmniAddress` variant: [3](#0-2) 

`OmniAddress` parsing is strict — an empty or malformed string panics the NEAR callback, permanently blocking finalization: [4](#0-3) 

The EVM contract has **no admin rescue function** and **no refund path** for a transfer whose NEAR-side finalization fails. The `completedTransfers` mapping is only used to prevent replay of `finTransfer`, not to enable refunds: [5](#0-4) 

The Solana bridge's `SECURITY.md` explicitly acknowledges the same class of missing validation as a known issue on that chain ("An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed"), but the EVM contract carries no such acknowledgment and provides no manual-intervention path: [6](#0-5) 

---

### Impact Explanation

A user who calls `initTransfer` (or `initTransfer1155`) with `recipient = ""`:

1. Has their tokens burned (bridge token) or transferred into the contract (native token) on EVM — irreversible.
2. Triggers an `InitTransfer` event with an empty recipient string.
3. Causes every relayer attempt to finalize the transfer on NEAR to panic and fail.
4. Has no on-chain mechanism to recover the locked/burned tokens.

Result: **permanent freezing of bridged funds on the EVM side**, matching the "permanent freezing of bridged funds" criterion in the allowed impact scope.

---

### Likelihood Explanation

Any unprivileged user can call `initTransfer` directly. Realistic trigger paths include:

- A DApp or SDK with a bug that passes an uninitialized or empty recipient string.
- A user interacting directly with the contract (e.g., via Etherscan) who omits the recipient.
- A programmatic bridge integration that fails to populate the recipient field before submission.

No admin compromise, social engineering, or privileged access is required.

---

### Recommendation

Add an explicit non-empty check for `recipient` in both `initTransfer` and `initTransfer1155`, mirroring the pattern already used in Starknet's `init_transfer` (`assert(amount > 0, 'ERR_ZERO_AMOUNT')`):

```solidity
error InvalidRecipient();

function initTransfer(
    address tokenAddress,
    uint128 amount,
    uint128 fee,
    uint128 nativeFee,
    string calldata recipient,
    string calldata message
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
+   if (bytes(recipient).length == 0) revert InvalidRecipient();
    if (fee >= amount) revert InvalidFee();
    // …
}
```

Apply the same guard to `initTransfer1155`.

---

### Proof of Concept

```solidity
// Attacker (or mistaken user) holds bridge tokens
BridgeToken(tokenAddress).approve(address(omniBridge), 1000);

// Call initTransfer with empty recipient — passes all existing checks
omniBridge.initTransfer(
    tokenAddress,
    1000,   // amount
    0,      // fee (0 < 1000, passes fee check)
    0,      // nativeFee
    "",     // recipient — empty, not validated
    ""      // message
);
// Tokens are now burned. InitTransfer event emitted with recipient="".
// Every NEAR fin_transfer attempt panics on OmniAddress deserialization.
// Funds are permanently frozen with no recovery path.
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-45)
```text
    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
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

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```

**File:** near/omni-types/src/lib.rs (L275-297)
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
    }
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
