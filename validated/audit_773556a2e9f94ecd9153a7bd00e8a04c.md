### Title
Missing Zero-Address Validation in `initialize()` Enables Signature Verification Bypass — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`OmniBridge.sol`'s `initialize()` function accepts `nearBridgeDerivedAddress_` — the sole address used to authenticate every MPC-signed cross-chain message — without any zero-address guard. If this parameter is `address(0)` at deployment (accidental or via front-run of the public `initializer`), the ECDSA signature check in `finTransfer` and `deployToken` degenerates to verifying that a recovered address equals `address(0)`, which is achievable with a crafted invalid signature under OpenZeppelin v4.x ECDSA semantics. The result is a complete authorization bypass: any caller can finalize arbitrary transfers and drain or mint bridged tokens.

---

### Finding Description

`OmniBridge.sol` is a UUPS-upgradeable contract. Its `initialize()` function is `public` and guarded only by the `initializer` modifier:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // ← no zero-check
    omniBridgeChainId = omniBridgeChainId_;
    ...
}
``` [1](#0-0) 

`nearBridgeDerivedAddress` is the only trust anchor for inbound cross-chain authorization. Every call to `finTransfer` (which releases or mints bridged tokens) and `deployToken` (which registers new bridge tokens) passes through this single check:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [2](#0-1) 

If `nearBridgeDerivedAddress` is `address(0)`, the guard becomes: *"revert unless the recovered signer is `address(0)`."* Under OpenZeppelin ECDSA v4.x, `ECDSA.recover` returns `address(0)` for certain malformed signatures (e.g., `v` not in `{27, 28}`, or `s` in the upper half of the curve) rather than reverting. An attacker who knows this can supply such a signature, causing `ECDSA.recover` to return `address(0)`, satisfying `address(0) == nearBridgeDerivedAddress`, and bypassing the check entirely.

The same pattern applies to `tokenImplementationAddress_`: if zero, every `deployToken` call creates an `ERC1967Proxy` pointing to `address(0)`, producing permanently broken bridge-token contracts. [3](#0-2) 

An identical structural gap exists in the Starknet bridge constructor, where `omni_bridge_derived_address: EthAddress` (the equivalent signature-verification anchor) is written without a zero-value guard:

```cairo
fn constructor(
    ref self: ContractState,
    omni_bridge_derived_address: EthAddress,   // ← no zero-check
    ...
) {
    self.omni_bridge_derived_address.write(omni_bridge_derived_address);
``` [4](#0-3) 

---

### Impact Explanation

- **Authorization bypass / unauthorized minting and fund theft (Critical).** With `nearBridgeDerivedAddress == address(0)` and OZ ECDSA v4.x, any unprivileged caller can invoke `finTransfer` with a crafted malformed signature, pass the signature check, and cause the bridge to release locked ERC-20 tokens or mint bridge tokens to an arbitrary recipient — without any valid NEAR MPC authorization. This directly enables theft of all funds locked in the bridge.
- **Unauthorized token deployment.** The same bypass applies to `deployToken`, allowing an attacker to register arbitrary token metadata and corrupt the `nearToEthToken` / `ethToNearToken` mappings, enabling subsequent token-confusion attacks.

---

### Likelihood Explanation

The `initialize()` function is `public` and callable by anyone before the proxy owner calls it (front-run window during deployment). Even absent front-running, a deployment script error passing `address(0)` for `nearBridgeDerivedAddress_` produces the same broken state with no on-chain recovery path (the field has no post-init setter visible in the searched code). The UUPS pattern means the implementation is deployed first and the proxy initialized in a separate transaction, widening the front-run window. The likelihood is **medium** for accidental misconfiguration and **low-to-medium** for deliberate front-running, but the impact is **critical** and irreversible once the initializer is consumed.

---

### Recommendation

Add explicit zero-address guards at the top of `initialize()` in `OmniBridge.sol`:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    require(tokenImplementationAddress_ != address(0), "zero tokenImpl");
    require(nearBridgeDerivedAddress_  != address(0), "zero nearBridgeAddr");
    ...
}
```

Apply the same pattern to `ENearProxy.initialize()` for `_eNear`, `_prover`, and `_adminAddress`, and to the Starknet constructor for `omni_bridge_derived_address`, `default_admin`, and `strk_token_address`.

---

### Proof of Concept

1. Attacker monitors the mempool for the `OmniBridge` proxy deployment transaction.
2. Attacker front-runs (or the deployer accidentally submits) `initialize(address(0), address(0), chainId)`.
3. `nearBridgeDerivedAddress` is now `address(0)`.
4. Attacker constructs a `FinTransferArgs` payload directing funds to their address, and supplies a signature with `v = 0` (invalid, causes OZ v4.x `ECDSA.recover` to return `address(0)`).
5. Attacker calls `finTransfer(args, invalidSig)`.
6. The check `ECDSA.recover(hashed, invalidSig) != address(0)` evaluates to `address(0) != address(0)` → `false` → no revert.
7. The bridge releases or mints tokens to the attacker's chosen recipient.
8. All locked user funds are drained. [1](#0-0) [2](#0-1) [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L162-172)
```text
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );
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
