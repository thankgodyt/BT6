### Title
Unvalidated `nearBridgeDerivedAddress_` in `initialize()` Enables Signature-Verification Bypass Leading to Unauthorized Fund Release — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary
`OmniBridge.sol`'s `initialize()` function assigns the critical `nearBridgeDerivedAddress` state variable directly from the caller-supplied `nearBridgeDerivedAddress_` parameter with no zero-address guard. This address is the sole signer authority checked in both `finTransfer()` and `deployToken()`. If it is initialized to `address(0)`, the ECDSA recovery check degenerates: any signature whose `ecrecover` output is `address(0)` (the canonical return value for an invalid/malformed signature in OpenZeppelin ECDSA v4) will satisfy the equality test, allowing an unprivileged attacker to finalize arbitrary transfers and drain bridged funds.

---

### Finding Description

`OmniBridge.initialize()` stores the three constructor arguments without any validation: [1](#0-0) 

`nearBridgeDerivedAddress` is then used as the sole trusted signer in two critical paths:

**`finTransfer()` — releases tokens/ETH to an arbitrary recipient:** [2](#0-1) 

**`deployToken()` — deploys a new bridge token and registers its mapping:** [3](#0-2) 

OpenZeppelin ECDSA v4's `recover()` returns `address(0)` for a degenerate/invalid signature rather than reverting. If `nearBridgeDerivedAddress == address(0)`, the guard `ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress` evaluates to `false` for any crafted invalid signature, so the `revert InvalidSignature()` branch is never taken.

The `setNearBridgeDerivedAddress()` setter exists but is gated behind `DEFAULT_ADMIN_ROLE`: [4](#0-3) 

There is a window between deployment and the admin correction call during which the contract is fully exploitable.

The same pattern is present in the Starknet bridge constructor, where `omni_bridge_derived_address` (the EVM signer used in `_verify_borsh_signature`) is written without a zero check: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

If `nearBridgeDerivedAddress` is `address(0)` at deployment time, any unprivileged caller can:

1. Call `finTransfer()` with a crafted invalid signature (e.g., all-zero `r`, `s`, `v=27`). `ECDSA.recover()` returns `address(0)`, matching the stored value. The nonce is marked used and the contract releases ETH, ERC-20, ERC-1155, or mints bridge tokens to an attacker-controlled `payload.recipient`.
2. Call `deployToken()` with the same technique to register arbitrary token mappings, poisoning the `nearToEthToken` / `ethToNearToken` tables and enabling future minting of unbacked tokens.

This constitutes unauthorized minting, permanent loss of bridged funds, and authorization bypass — all within the Critical impact scope.

---

### Likelihood Explanation

The `initialize()` function is called exactly once, by the deployer, immediately after proxy deployment. A deployment script that passes a zero or unset address (e.g., a misconfigured environment variable, a staging address left as the default) silently produces a live contract in the exploitable state. The window between `initialize()` and a corrective `setNearBridgeDerivedAddress()` call is publicly observable on-chain, and any attacker monitoring the mempool or block explorer can exploit it before the admin acts.

---

### Recommendation

Add explicit zero-address guards inside `initialize()` for both `tokenImplementationAddress_` and `nearBridgeDerivedAddress_`:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    require(tokenImplementationAddress_ != address(0), "ERR_ZERO_TOKEN_IMPL");
    require(nearBridgeDerivedAddress_ != address(0), "ERR_ZERO_SIGNER");
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    omniBridgeChainId = omniBridgeChainId_;
    // ...
}
```

Apply the same guard to the Starknet constructor for `omni_bridge_derived_address` and `default_admin`.

---

### Proof of Concept

1. Deploy `OmniBridge` proxy and call `initialize(validImpl, address(0), chainId)`.
2. Construct a `TransferMessagePayload` with `recipient = attacker`, `tokenAddress = <any ERC-20 held by bridge>`, `amount = bridge_balance`.
3. Produce an invalid 65-byte signature (e.g., `bytes(65)`).
4. Call `finTransfer(invalidSig, payload)`.
5. `ECDSA.recover(hashed, invalidSig)` returns `address(0)`.
6. `address(0) != address(0)` is `false` → no revert.
7. `completedTransfers[nonce]` is set; tokens are transferred to attacker. [7](#0-6)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```

**File:** starknet/src/omni_bridge.cairo (L122-139)
```text
    #[constructor]
    fn constructor(
        ref self: ContractState,
        omni_bridge_derived_address: EthAddress,
        omni_bridge_chain_id: u8,
        token_class_hash: ClassHash,
        default_admin: ContractAddress,
        strk_token_address: ContractAddress,
    ) {
        self.omni_bridge_derived_address.write(omni_bridge_derived_address);
        self.omni_bridge_chain_id.write(omni_bridge_chain_id);
        self.bridge_token_class_hash.write(token_class_hash);
        self.strk_token_address.write(strk_token_address);
        self.pause_flags.write(0);

        self.accesscontrol.initializer();
        self.accesscontrol._grant_role(DEFAULT_ADMIN_ROLE, default_admin);
    }
```

**File:** starknet/src/omni_bridge.cairo (L398-406)
```text
    fn _verify_borsh_signature(
        ref self: ContractState, borsh_bytes: @ByteArray, signature: Signature,
    ) {
        let message_hash_le = compute_keccak_byte_array(borsh_bytes);
        let message_hash = reverse_u256_bytes(message_hash_le);

        let sig = signature_from_vrs(signature.v, signature.r, signature.s);
        verify_eth_signature(message_hash, sig, self.omni_bridge_derived_address.read());
    }
```
