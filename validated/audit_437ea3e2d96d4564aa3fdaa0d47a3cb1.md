### Title
Missing Zero Address Check for `nearBridgeDerivedAddress` in `initialize()` Enables Complete MPC Signature Bypass — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `initialize()` function sets `nearBridgeDerivedAddress` — the address used to verify every MPC signature in `finTransfer` — without a zero address check. If accidentally set to `address(0)`, any attacker can call `finTransfer` with a deliberately invalid signature (for which `ecrecover` returns `address(0)`), pass signature verification, and mint or unlock arbitrary amounts of bridged tokens.

---

### Finding Description

`OmniBridge.sol` is a UUPS upgradeable contract. Its `initialize()` function is the sole place where `nearBridgeDerivedAddress` is written: [1](#0-0) 

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // ← no zero check
    omniBridgeChainId = omniBridgeChainId_;
    ...
}
```

`nearBridgeDerivedAddress` is the Ethereum address derived from the NEAR MPC network's public key. Every inbound transfer finalization (`finTransfer`) recovers the signer from the MPC-produced ECDSA signature and asserts it equals `nearBridgeDerivedAddress`. This is the sole cryptographic gate preventing unauthorized minting or unlocking of bridged tokens on the EVM side. [2](#0-1) 

The `initializer` modifier (OpenZeppelin) ensures `initialize()` can be called exactly once. There is no post-deployment setter for `nearBridgeDerivedAddress` visible in the contract, meaning a misconfiguration at deployment time is permanent without a full UUPS upgrade.

---

### Impact Explanation

`ecrecover` returns `address(0)` for any signature that does not correspond to a valid secp256k1 signing operation (e.g., `v`, `r`, `s` values that produce no valid public key). If `nearBridgeDerivedAddress == address(0)`, the check:

```
ecrecover(hash, v, r, s) == nearBridgeDerivedAddress
```

evaluates to `true` for any such crafted invalid signature. An attacker can:

1. Construct a `finTransfer` payload with an arbitrary recipient and amount.
2. Supply a deliberately invalid signature (e.g., `r = s = 0`, `v = 27`).
3. Call `finTransfer` — verification passes.
4. Receive minted bridge tokens or unlocked native tokens with no legitimate cross-chain transfer having occurred.

This constitutes **unauthorized minting / complete MPC signature verification bypass**, enabling theft of all bridged funds held or mintable by the contract.

---

### Likelihood Explanation

The `initialize()` function is called once, typically by a deployment script. A copy-paste error, a misconfigured environment variable, or a script that passes a zero default for an unset parameter is a realistic deployment mistake — exactly the class of error the original finding describes. Because the `initializer` modifier prevents re-initialization, the window to detect and correct the error before exploitation is narrow. The UUPS upgrade path exists but requires governance action and introduces its own delay.

---

### Recommendation

Add an explicit zero address guard in `initialize()` for both `nearBridgeDerivedAddress_` and `tokenImplementationAddress_`:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    require(nearBridgeDerivedAddress_ != address(0), "zero nearBridgeDerivedAddress");
    require(tokenImplementationAddress_ != address(0), "zero tokenImplementation");
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    omniBridgeChainId = omniBridgeChainId_;
    ...
}
```

Additionally, consider adding a post-deployment setter restricted to `DEFAULT_ADMIN_ROLE` so that a misconfiguration can be corrected without a full contract upgrade.

---

### Proof of Concept

1. Deploy `OmniBridge` proxy and call `initialize(validImpl, address(0), chainId)` — no revert occurs.
2. `nearBridgeDerivedAddress` is now `address(0)`.
3. Attacker constructs:
   - A `finTransfer` payload crediting `attacker` with `1_000_000e18` of a bridged token.
   - An invalid signature: `v = 27, r = bytes32(0), s = bytes32(0)` (or any values for which `ecrecover` returns `address(0)`).
4. Attacker calls `finTransfer(payload, invalidSig)`.
5. Signature check: `ecrecover(...) == address(0) == nearBridgeDerivedAddress` → passes.
6. Bridge mints or transfers `1_000_000e18` tokens to attacker. [1](#0-0)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L40-42)
```text
    address public tokenImplementationAddress;
    address public nearBridgeDerivedAddress;
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
