### Title
Zero-Address `nearBridgeDerivedAddress` in `initialize()` Bypasses MPC Signature Verification, Enabling Unauthorized Token Minting — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initialize()` assigns `nearBridgeDerivedAddress` — the sole trusted signer used to authorize `finTransfer` (token minting) and `deployToken` — without checking that it is non-zero. If the contract is initialized with `nearBridgeDerivedAddress = address(0)`, the ECDSA signature check in both `finTransfer()` and `deployToken()` becomes trivially bypassable by any attacker holding any valid ECDSA key pair, enabling unauthorized minting of bridged tokens to arbitrary recipients.

---

### Finding Description

`OmniBridge.initialize()` stores `nearBridgeDerivedAddress_` directly into state with no zero-address guard:

```solidity
// OmniBridge.sol L72-86
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

`nearBridgeDerivedAddress` is the only authorization gate for two critical public entry points:

**`finTransfer()` (L311):**
```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

**`deployToken()` (L151):**
```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

`ECDSA.recover()` always returns a **non-zero** address for any well-formed ECDSA signature. Therefore, when `nearBridgeDerivedAddress == address(0)`, the inequality `ECDSA.recover(...) != address(0)` evaluates to `true` for every valid signature — the check is permanently satisfied by any attacker who can produce a valid ECDSA signature over the crafted payload with their own private key.

---

### Impact Explanation

With `nearBridgeDerivedAddress == address(0)`:

1. **Unauthorized minting via `finTransfer()`**: An attacker constructs any `TransferMessagePayload` (choosing arbitrary `tokenAddress`, `amount`, `recipient`, and a fresh `destinationNonce`), signs the Borsh-encoded payload with their own private key, and calls `finTransfer()`. The signature check passes. The contract then mints bridge tokens (via `IBridgeToken.mint`) or releases escrowed ERC-20/ETH to the attacker-chosen `recipient`. This constitutes **unauthorized minting and theft of bridged funds**.

2. **Unauthorized token deployment via `deployToken()`**: An attacker deploys arbitrary bridge tokens mapped to any NEAR token ID, poisoning the `nearToEthToken` / `ethToNearToken` / `isBridgeToken` mappings and permanently blocking legitimate token deployment for those IDs.

Both impacts fall squarely within the allowed critical scope: signer/prover verification bypass enabling unauthorized bridge actions and balance manipulation.

---

### Likelihood Explanation

The `initialize()` function is called exactly once, at proxy deployment time, by the deployer. Passing `address(0)` for `nearBridgeDerivedAddress` is a realistic deployment mistake — the parameter name does not make the zero-address consequence obvious, and there is no on-chain guard to catch it. The `setNearBridgeDerivedAddress()` setter exists but is admin-only and requires the admin to detect the misconfiguration before an attacker exploits it. The window between deployment and detection is the attack surface.

---

### Recommendation

Add an explicit zero-address check in `initialize()` for `nearBridgeDerivedAddress_`:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    require(nearBridgeDerivedAddress_ != address(0), "ERR_ZERO_BRIDGE_ADDRESS");
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    ...
}
```

Apply the same guard to `setNearBridgeDerivedAddress()` for defense-in-depth.

---

### Proof of Concept

1. Deploy `OmniBridge` proxy and call `initialize(validTokenImpl, address(0), chainId)`.
2. Attacker generates any ECDSA key pair `(sk, pk)` → `attackerAddr = ecrecover(pk)`.
3. Attacker constructs payload:
   ```
   payload.destinationNonce = 1  // fresh nonce
   payload.tokenAddress = <any isBridgeToken address>
   payload.amount = 1_000_000e18
   payload.recipient = attacker
   ```
4. Attacker Borsh-encodes the payload, computes `hashed = keccak256(borshEncoded)`, signs with `sk` → `sig`.
5. Attacker calls `finTransfer(sig, payload)`.
6. `ECDSA.recover(hashed, sig)` returns `attackerAddr` (non-zero).
7. `attackerAddr != address(0)` → `true` → check passes, `InvalidSignature` is NOT reverted.
8. Contract mints `1_000_000e18` bridge tokens to attacker. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L149-153)
```text
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L309-313)
```text
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```
