### Title
Missing Zero-Address Check on `nearBridgeDerivedAddress` Bypasses the Sole Signature Authorization Gate for Token Minting and Transfer — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.initialize` and `setNearBridgeDerivedAddress` accept `nearBridgeDerivedAddress_` without any zero-address guard. `nearBridgeDerivedAddress` is the **only** authorization gate for `finTransfer` (which mints or releases bridged tokens) and `deployToken`. If it is set to `address(0)` — either at initialization or via the admin setter — an attacker can bypass signature verification entirely (OpenZeppelin ECDSA v4.x) or permanently freeze all NEAR→EVM transfers (OpenZeppelin ECDSA v5.x).

### Finding Description

`OmniBridge.initialize` stores `nearBridgeDerivedAddress_` unconditionally:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,   // ← no zero-address check
    uint8 omniBridgeChainId_
) public initializer {
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // stored as-is
    ...
}
``` [1](#0-0) 

The post-deployment admin setter has the same omission:

```solidity
function setNearBridgeDerivedAddress(
    address nearBridgeDerivedAddress_
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // ← no zero-address check
}
``` [2](#0-1) 

`nearBridgeDerivedAddress` is then used as the sole authorization gate in both `finTransfer` and `deployToken`:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [3](#0-2) [4](#0-3) 

The project's own security invariant explicitly states:

> **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer. [5](#0-4) 

The same pattern is present in `OmniBridgeWormhole.initializeWormhole`, which calls `initialize` with the same unchecked parameter, and in `setWormholeAddress`, which stores `wormholeAddress` without a zero-address check. [6](#0-5) [7](#0-6) 

### Impact Explanation

**Scenario A — OpenZeppelin ECDSA v4.x (recover returns `address(0)` for malformed signatures):**
If `nearBridgeDerivedAddress == address(0)`, an attacker crafts a signature for which `ECDSA.recover` returns `address(0)` (e.g., by supplying an invalid `v` value). The check `ECDSA.recover(...) != nearBridgeDerivedAddress` evaluates to `address(0) != address(0)` → `false`, so no revert occurs. The attacker then proceeds through `finTransfer` to mint or transfer arbitrary amounts of any registered bridge token to any recipient, or through `deployToken` to register arbitrary token metadata. This is a complete authorization bypass enabling unauthorized minting and theft of bridged funds.

**Scenario B — OpenZeppelin ECDSA v5.x (recover reverts on `address(0)` recovery):**
`ECDSA.recover` reverts with `ECDSAInvalidSignature` for any signature that would recover to `address(0)`. Since no valid signature can ever recover to `address(0)`, `finTransfer` and `deployToken` become permanently unusable. All NEAR→EVM transfers are permanently blocked, freezing all bridged funds that users have already committed on the NEAR side.

Both outcomes are critical: unauthorized minting/token release (Scenario A) or permanent freezing of bridged funds (Scenario B).

### Likelihood Explanation

The `initialize` function is called once at deployment with no on-chain enforcement preventing a zero value. The `setNearBridgeDerivedAddress` setter is callable by any `DEFAULT_ADMIN_ROLE` holder at any time with no guard. Accidental misconfiguration (e.g., passing a zero address due to a scripting error, a missing environment variable, or a copy-paste mistake) is a realistic operational risk, as documented by the analogous finding in the external report. The bridge is deployed across at least seven EVM chains (Ethereum, Arbitrum, Base, BNB, Polygon, HyperEVM, Abstract), multiplying the deployment surface. [8](#0-7) 

### Recommendation

Add a zero-address guard in both `initialize` and `setNearBridgeDerivedAddress`:

```solidity
require(nearBridgeDerivedAddress_ != address(0), "ERR_ZERO_BRIDGE_ADDRESS");
```

Apply the same guard to `tokenImplementationAddress_` in `initialize` (already partially guarded in `deployToken` via `TokenImplementationNotSet`, but not at initialization time) and to `wormholeAddress` in `OmniBridgeWormhole.setWormholeAddress`.

### Proof of Concept

**Scenario A (OZ ECDSA v4.x — signature bypass):**

1. Deployer calls `initialize(implAddr, address(0), chainId)` — either accidentally or via a misconfigured deployment script.
2. `nearBridgeDerivedAddress` is now `address(0)`.
3. Attacker constructs a `TransferMessagePayload` with `recipient = attacker`, `tokenAddress = <any registered bridge token>`, `amount = MAX_UINT128`, and a `destinationNonce` not yet used.
4. Attacker supplies a 65-byte signature with `v = 0` (or any value that causes OZ v4 `ECDSA.recover` to return `address(0)`).
5. `ECDSA.recover(hashed, signatureData)` returns `address(0)`.
6. Check: `address(0) != address(0)` → `false` → no revert.
7. `finTransfer` proceeds to mint `MAX_UINT128` tokens to the attacker. [9](#0-8) 

**Scenario B (OZ ECDSA v5.x — permanent freeze):**

1. Same initialization mistake as above.
2. Any relayer attempts to call `finTransfer` with a legitimate MPC signature.
3. `ECDSA.recover` reverts with `ECDSAInvalidSignature` because no valid signature recovers to `address(0)`.
4. All NEAR→EVM transfers are permanently blocked. Funds committed on the NEAR side cannot be released on any EVM chain. [3](#0-2)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-153)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-355)
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

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```

**File:** evm/CLAUDE.md (L35-35)
```markdown
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L32-46)
```text
    function initializeWormhole(
        address tokenImplementationAddress,
        address nearBridgeDerivedAddress,
        uint8 omniBridgeChainId,
        address wormholeAddress,
        uint8 consistencyLevel
    ) external initializer {
        initialize(
            tokenImplementationAddress,
            nearBridgeDerivedAddress,
            omniBridgeChainId
        );
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L152-158)
```text
    function setWormholeAddress(
        address wormholeAddress,
        uint8 consistencyLevel
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
```

**File:** README.md (L22-41)
```markdown
<details>
<summary><strong>Mainnet Addresses</strong></summary>

**Bridge Contracts:**
- Arbitrum: [`0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`](https://arbiscan.io/address/0xd025b38762B4A4E36F0Cde483b86CB13ea00D989)
- Base: [`0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`](https://basescan.org/address/0xd025b38762B4A4E36F0Cde483b86CB13ea00D989)
- Bnb: [`0x073C8a225c8Cf9d3f9157F5C1a1DbE02407f5720`](https://bscscan.com/address/0x073C8a225c8Cf9d3f9157F5C1a1DbE02407f5720)
- Polygon: [`0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`](https://polygonscan.com/address/0xd025b38762B4A4E36F0Cde483b86CB13ea00D989)
- Ethereum: [`0xe00c629aFaCCb0510995A2B95560E446A24c85B9`](https://etherscan.io/address/0xe00c629aFaCCb0510995A2B95560E446A24c85B9)
- NEAR: [`omni.bridge.near`](https://nearblocks.io/address/omni.bridge.near)
- Solana: [`dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe`](https://explorer.solana.com/address/dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe)

**Helper Contracts:**
- NEAR: 
  - [`vaa-prover-0_4_3.bridge.near`](https://nearblocks.io/address/vaa-prover-0_4_3.bridge.near)
  - [`vaa-prover-0_4_1.bridge.near`](https://nearblocks.io/address/vaa-prover-0_4_1.bridge.near)
  - [`eth-prover-0_4_1.bridge.near`](https://nearblocks.io/address/eth-prover-0_4_1.bridge.near)
  - [`omdep.near`](https://nearblocks.io/address/omdep.near)
  - [`factory.bridge.near`](https://nearblocks.io/address/factory.bridge.near)
</details>
```
