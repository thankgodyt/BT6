### Title
Missing EVM `block.chainid` in `finTransfer` Signed Payload Enables Cross-Chain Replay After Hard Fork - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.finTransfer` constructs its Borsh-encoded signed payload using `omniBridgeChainId` (a custom 1-byte protocol identifier) instead of the EVM-native `block.chainid`. After an EVM hard fork both chains share the same `omniBridgeChainId` value and the same `nearBridgeDerivedAddress`, so any NEAR-MPC-signed `finTransfer` payload accepted on the canonical chain is equally valid on the forked chain. Because `completedTransfers` is independent state on each chain, a nonce consumed on the canonical chain is still open on the fork, allowing an attacker to replay the transfer and receive tokens twice.

### Finding Description
`finTransfer` in `OmniBridge.sol` builds the message that NEAR MPC signs as follows:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),          // ← protocol byte, NOT block.chainid
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),          // ← same protocol byte again
    Borsh.encodeAddress(payload.recipient),
    ...
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

`omniBridgeChainId` is a `uint8` set once at `initialize()` time and stored in contract state. It is the Omni Bridge protocol's internal chain identifier (e.g. `1` for Ethereum), not the EVM consensus-layer `block.chainid` (e.g. `1` for Ethereum mainnet, `61` for Ethereum Classic). After a hard fork both chains retain the same `omniBridgeChainId` and the same `nearBridgeDerivedAddress`, so the ECDSA signature is equally valid on both chains. The only replay guard is `completedTransfers[payload.destinationNonce]`, which is independent per-chain state and is not shared across a fork.

The `evm/SECURITY.md` explicitly documents that `deployToken` is intentionally chain-agnostic ("one NEAR-side signature deploys the same token on all EVM chains"), but makes no such statement for `finTransfer`. The omission in `finTransfer` is therefore an unintentional vulnerability, not a design decision.

### Impact Explanation
After an EVM hard fork an attacker can take any `finTransfer` calldata (signature + payload) that was submitted on the canonical chain after the fork point and replay it on the forked chain. The `completedTransfers` mapping on the fork does not contain that nonce, so the replay succeeds. The contract then mints or transfers the full token amount to the recipient on the forked chain. This constitutes double-spending: the user receives tokens on both chains while the NEAR side only records a single outbound transfer. For native-token transfers (`tokenAddress == address(0)`) the contract sends ETH from its own balance, draining the vault on the forked chain.

### Likelihood Explanation
EVM hard forks are rare but have occurred with significant financial impact (ETH/ETC split 2016, ETH PoW fork 2022 at the Merge). The attack requires no privileged access: any observer can collect signed `finTransfer` calldata from the canonical chain's mempool or transaction history and replay it on the fork. The window of opportunity is every transfer signed by NEAR MPC that is submitted to the canonical chain after the fork block but whose nonce has not yet been consumed on the forked chain. Relayers routinely batch and delay submissions, widening this window.

### Recommendation
Include `block.chainid` in the Borsh-encoded payload that NEAR MPC signs, so that a signature produced for one EVM chain is cryptographically bound to that chain's consensus-layer ID and cannot be accepted on any other chain:

```solidity
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
    Borsh.encodeUint256(block.chainid),   // ← add EVM chain ID
    ...
);
```

The NEAR side must include `block.chainid` when constructing the payload before requesting the MPC signature. This is the standard EIP-155 / EIP-712 domain-separation approach.

### Proof of Concept

1. At block N (pre-fork) a user initiates a NEAR → Ethereum transfer. NEAR MPC signs a `finTransfer` payload for `destinationNonce = 42`.
2. The EVM hard fork occurs at block N+1. Both chains now have identical `completedTransfers` state (nonce 42 unused on both).
3. A relayer submits `finTransfer(sig, payload)` on the canonical chain at block N+2. `completedTransfers[42]` is set to `true` on the canonical chain; tokens are minted to the recipient.
4. An attacker copies the identical calldata and submits it on the forked chain. `completedTransfers[42]` is still `false` there. `ECDSA.recover(keccak256(borshEncoded), sig)` returns `nearBridgeDerivedAddress` (same on both chains). The check passes. Tokens are minted again to the recipient on the forked chain.
5. The recipient now holds tokens on both chains; the NEAR bridge escrow has only been debited once.

**Relevant code locations:** [1](#0-0) 

`omniBridgeChainId` is a stored `uint8`, not `block.chainid`: [2](#0-1) 

Initialized once and never updated: [3](#0-2) 

The `deployToken` chain-agnostic design is explicitly documented as intentional, but `finTransfer` is not: [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L42-43)
```text
    uint8 public omniBridgeChainId;

```

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

**File:** evm/SECURITY.md (L10-10)
```markdown
- **`deployToken` signature has no chain ID**: Metadata signatures are intentionally chain-agnostic — one NEAR-side signature deploys the same token on all EVM chains
```
