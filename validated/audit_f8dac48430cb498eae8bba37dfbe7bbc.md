### Title
Missing Zero-Address Validation for `nearBridgeDerivedAddress` in `initialize()` Permanently Disables Signature Verification Gate - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `initialize()` function assigns `nearBridgeDerivedAddress` directly from the caller-supplied parameter without any zero-address check. This address is the **sole authorization gate** for both `finTransfer()` and `deployToken()`. If it is set to `address(0)` at initialization, every subsequent call to those functions will permanently revert with `InvalidSignature`, freezing all bridged funds with no on-chain recovery path other than a UUPS upgrade.

---

### Finding Description

`OmniBridge.initialize()` stores three constructor-equivalent parameters: [1](#0-0) 

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // ← no zero-check
    ...
}
```

`nearBridgeDerivedAddress` is then used as the exclusive signer check in both critical outbound paths:

**`finTransfer()` (line 311):** [2](#0-1) 

**`deployToken()` (line 151):** [3](#0-2) 

Both functions perform:
```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

There is **no setter function** for `nearBridgeDerivedAddress` anywhere in the contract. The only post-deployment remedy is a full UUPS implementation upgrade.

By contrast, `tokenImplementationAddress` already has a defensive guard in `deployToken()`: [4](#0-3) 

```solidity
if (tokenImplementationAddress == address(0)) {
    revert TokenImplementationNotSet();
}
```

No equivalent guard exists for `nearBridgeDerivedAddress`.

---

### Impact Explanation

If `nearBridgeDerivedAddress` is initialized to `address(0)`:

- Every `finTransfer()` call reverts with `InvalidSignature` because any legitimately MPC-signed payload recovers to a real secp256k1 address, never `address(0)`.
- Every `deployToken()` call reverts for the same reason.
- Tokens locked or burned on the NEAR side (via `initTransfer`) can never be released on the EVM side.
- **All bridged funds are permanently frozen** with no on-chain recovery path.

The NEAR → EVM flow is described in the architecture documentation as relying entirely on `finTransfer` with `nearBridgeDerivedAddress` as the only authorization gate: [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The `initialize()` function is called once, immediately after proxy deployment, by the deploying account. A deployment script error, copy-paste mistake, or misconfigured environment variable passing `address(0)` for `nearBridgeDerivedAddress_` would silently succeed (no revert at initialization time) and leave the contract in a permanently broken state. The `initializer` modifier prevents re-initialization, so there is no second chance.

---

### Recommendation

Add an explicit zero-address guard in `initialize()` for `nearBridgeDerivedAddress_`, mirroring the existing runtime guard already applied to `tokenImplementationAddress`:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    require(nearBridgeDerivedAddress_ != address(0), "Zero nearBridgeDerivedAddress");
    require(tokenImplementationAddress_ != address(0), "Zero tokenImplementationAddress");
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    ...
}
```

Additionally, consider adding a privileged setter for `nearBridgeDerivedAddress` (guarded by `DEFAULT_ADMIN_ROLE`) to allow recovery without a full implementation upgrade.

---

### Proof of Concept

1. Deploy the `OmniBridge` implementation contract.
2. Deploy a `ERC1967Proxy` pointing to it, calling `initialize(validTokenImpl, address(0), chainId)`.
3. Initialization succeeds silently — no revert.
4. A relayer attempts `finTransfer(validSignature, validPayload)`.
5. `ECDSA.recover(hashed, validSignature)` returns the legitimate MPC-derived address (e.g., `0xABCD...`).
6. `0xABCD... != address(0)` → `revert InvalidSignature()`.
7. All `finTransfer` and `deployToken` calls revert permanently. Funds locked on NEAR via `initTransfer` events can never be released on the EVM side. [1](#0-0) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-86)
```text
    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init_unchained();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L139-141)
```text
        if (tokenImplementationAddress == address(0)) {
            revert TokenImplementationNotSet();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-153)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-313)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/CLAUDE.md (L21-21)
```markdown
**NEAR → EVM (finTransfer)**: A relayer submits a NEAR MPC signature over a Borsh-encoded `TransferMessagePayload`. The contract verifies the signature against `nearBridgeDerivedAddress`, marks the `destinationNonce` as used, then mints/transfers tokens to the recipient. Emits `FinTransfer`.
```

**File:** evm/CLAUDE.md (L35-35)
```markdown
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
```
