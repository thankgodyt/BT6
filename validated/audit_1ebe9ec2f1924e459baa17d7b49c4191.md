### Title
Silent Success on Non-Contract `tokenAddress` in `initTransfer1155` Enables Unauthorized NEAR Token Minting Without Locking ERC1155 Assets - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`initTransfer1155` in `OmniBridge.sol` calls `IERC1155(tokenAddress).safeTransferFrom(...)` — a void interface function — without verifying that `tokenAddress` contains deployed contract code. When `tokenAddress` is an EOA or a codeless address, the EVM `CALL` opcode returns `(true, "")` and Solidity silently accepts the result because no return value is expected. The `InitTransfer` event is emitted as if real ERC1155 tokens were locked, and the NEAR bridge mints the corresponding bridged tokens on NEAR — with zero collateral locked on EVM.

---

### Finding Description

`initTransfer1155` is a permissionless public function. It derives a `deterministicToken` address from `(tokenAddress, tokenId)`, calls `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")`, and unconditionally emits `BridgeTypes.InitTransfer`. [1](#0-0) 

`IERC1155.safeTransferFrom` is declared `external` with no return value:

```solidity
function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
```

In Solidity ≥ 0.8, a high-level call to an address with no deployed bytecode still executes the EVM `CALL` opcode, which returns `(1, "")`. Because the callee is a void function, the compiler emits no `returndatasize` check and no revert. Execution continues normally.

The companion function `logMetadata1155` is equally permissionless and stores the `(tokenAddress, tokenId)` mapping in `multiTokens[deterministicToken]` without any `extcodesize` guard: [2](#0-1) 

It also emits a `LogMetadata` event that the NEAR bridge uses to deploy the bridged token on NEAR: [3](#0-2) 

The NEAR bridge's `deploy_token_callback` accepts any `LogMetadata` proof emitted by the registered factory and deploys the corresponding NEP-141 token: [4](#0-3) 

---

### Impact Explanation

An attacker can mint an unbounded quantity of bridged ERC1155-backed tokens on NEAR without depositing any ERC1155 collateral on EVM. The `InitTransfer` event is indistinguishable from a legitimate lock event. The NEAR bridge verifies only that the event was emitted by the registered OmniBridge factory — which it was — and mints accordingly. This constitutes unauthorized minting and escrow mis-accounting: the NEAR-side supply grows while EVM-side collateral does not. [5](#0-4) 

---

### Likelihood Explanation

Both `logMetadata1155` and `initTransfer1155` are fully permissionless — no role, no whitelist, no prior registration required. Any externally-owned account can execute the full attack sequence in two transactions. No admin compromise, no leaked key, and no front-running dependency is needed. The only cost is gas. [6](#0-5) 

---

### Recommendation

**Short term:** Add an `extcodesize` guard at the top of `initTransfer1155` (and `logMetadata1155`) before accepting `tokenAddress`:

```solidity
uint256 size;
assembly { size := extcodesize(tokenAddress) }
require(size > 0, "ERR_NOT_CONTRACT");
```

**Long term:** Require that `multiTokens[deterministicToken]` is already populated (i.e., `logMetadata1155` was called and the mapping exists) before `initTransfer1155` proceeds. This enforces a two-step registration that gives operators a chance to validate the token contract before transfers are accepted.

---

### Proof of Concept

```
Step 1 — Register a fake token on NEAR:
  attacker calls OmniBridge.logMetadata1155(address(0xdead), 1)
  → multiTokens[deterministicToken] = {tokenAddress: 0xdead, tokenId: 1}
  → emits LogMetadata(deterministicToken, "0x000...dead", "", 0)
  → NEAR bridge processes proof, deploys NEP-141 token for deterministicToken

Step 2 — Fake-lock tokens:
  attacker calls OmniBridge.initTransfer1155(
      address(0xdead), 1,
      1_000_000,   // amount
      0,           // fee
      0,           // nativeFee
      "attacker.near",
      ""
  )
  → IERC1155(0xdead).safeTransferFrom(attacker, bridge, 1, 1_000_000, "")
    ↳ 0xdead has no code → EVM CALL returns (true, "")
    ↳ void function → no returndatasize check → silent success
  → emits InitTransfer(attacker, deterministicToken, nonce, 1_000_000, 0, 0, "attacker.near", "")

Step 3 — Collect on NEAR:
  Relayer submits InitTransfer proof to NEAR bridge
  → NEAR bridge verifies proof (emitter = registered factory ✓)
  → NEAR bridge mints 1_000_000 bridged tokens to attacker.near
  → Zero ERC1155 tokens were ever locked on EVM
``` [1](#0-0) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1155-1174)
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
```
