### Title
Silent ERC1155 `safeTransferFrom` on Non-Existent Token Address Enables Unauthorized NEP-141 Minting — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` calls `IERC1155(tokenAddress).safeTransferFrom(...)` — a void function — without verifying that `tokenAddress` has contract code. In Solidity, a high-level call to a void function on a codeless address silently returns success. Combined with the permissionless `logMetadata1155` (which also performs no code-existence check on `tokenAddress`), an attacker can register a not-yet-deployed ERC1155 address, trigger a silent "lock" of zero real tokens, and cause NEAR to mint an arbitrary amount of NEP-141 bridged tokens for free.

---

### Finding Description

**Root cause — `logMetadata1155` accepts any address without code check:**

`logMetadata1155` never calls any function on `tokenAddress`. It only stores the `(tokenAddress, tokenId)` pair in `multiTokens[deterministicToken]` and emits a `LogMetadata` event. There is no `require(tokenAddress.code.length > 0)` guard. [1](#0-0) 

This is explicitly confirmed as permissionless by design: [2](#0-1) 

**Root cause — `initTransfer1155` calls a void function on an unverified address:**

`IERC1155.safeTransferFrom` has no return value. In Solidity ≥0.8, a high-level call to a void function on an address with no deployed code returns `success = true` with empty returndata; Solidity has nothing to decode and does not revert. The bridge therefore believes tokens were locked when none were. [3](#0-2) 

Contrast this with the ERC-20 path in `initTransfer`, which uses OpenZeppelin's `SafeERC20.safeTransferFrom` — OZ's wrapper explicitly checks `address(token).code.length > 0` before calling, so the ERC-20 path is **not** affected. [4](#0-3) 

**Secondary impact — `finTransfer` also silently succeeds for the same non-existent address:**

When `finTransfer` is called for a `deterministicToken` whose backing ERC1155 has no code, the same void-function silent-success applies. The nonce is consumed and the recipient receives nothing. [5](#0-4) 

---

### Impact Explanation

An attacker can mint an unbounded quantity of NEP-141 bridged tokens on NEAR without locking any real ERC1155 tokens on EVM. This directly inflates the NEP-141 supply beyond the real ERC1155 collateral held by the bridge, making the bridge insolvent. Legitimate users who later bridge real ERC1155 tokens from NEAR back to EVM will find the bridge holds no collateral and their `finTransfer` calls silently consume nonces without delivering tokens — permanent loss of bridged funds.

---

### Likelihood Explanation

Both entry-point functions (`logMetadata1155` and `initTransfer1155`) are fully permissionless and callable by any EOA with no special role. The attack requires only two on-chain transactions and patience for the relayer to process the resulting events. The cross-chain same-address deployment pattern (the original M-25 motivation) is directly applicable: an attacker can target any ERC1155 token whose address is predictable before deployment (e.g., via CREATE2 or same-nonce deployer). Likelihood is high.

---

### Recommendation

1. **Add a code-existence check in `initTransfer1155`** before calling `safeTransferFrom`:
   ```solidity
   require(tokenAddress.code.length > 0, "ERC1155: token address has no code");
   ```
2. **Add the same guard in `logMetadata1155`** to prevent registering phantom tokens in `multiTokens` before the ERC1155 is deployed:
   ```solidity
   require(tokenAddress.code.length > 0, "ERC1155: token address has no code");
   ```
3. Alternatively, use a wrapper analogous to OZ's `SafeERC20` that performs a code-existence check before any ERC1155 call.

---

### Proof of Concept

**Step 1 — Register a non-existent ERC1155 address (permissionless):**
```solidity
// victimAddress has no code yet but will be deployed there in the future
bridge.logMetadata1155(victimAddress, tokenId);
// Succeeds: no call is made to victimAddress, mapping is written, LogMetadata emitted
``` [1](#0-0) 

**Step 2 — NEAR relayer processes `LogMetadata`, deploys NEP-141 token for `deterministicToken`.** [6](#0-5) 

**Step 3 — Attacker calls `initTransfer1155` with the non-existent address:**
```solidity
bridge.initTransfer1155(victimAddress, tokenId, 1_000_000e18, 0, 0, "attacker.near", "");
// IERC1155(victimAddress).safeTransferFrom(...) → void function, no code → silent success
// InitTransfer event emitted claiming 1_000_000e18 tokens locked
``` [7](#0-6) 

**Step 4 — NEAR relayer processes `InitTransfer` proof; `fin_transfer_callback` mints 1,000,000e18 NEP-141 tokens to attacker.** [8](#0-7) 

Attacker now holds 1,000,000e18 NEP-141 tokens backed by zero real ERC1155 collateral. Bridge is insolvent for all future legitimate redeemers.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-490)
```text
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

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```

**File:** near/omni-bridge/src/lib.rs (L704-718)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L1155-1175)
```rust
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
    }
```
