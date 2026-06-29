### Title
Mutable `nearBridgeDerivedAddress` Setter Allows Permanent Freezing of In-Flight Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` exposes a post-deployment setter `setNearBridgeDerivedAddress` that can overwrite the MPC-derived Ethereum address used to verify every `finTransfer` signature. If this parameter is updated while NEAR→EVM transfers are in-flight (NEAR has already locked/burned the user's tokens and the MPC has already signed the payload with the old key), those transfers will permanently fail signature verification on the EVM side. The user's tokens are irreversibly locked on NEAR with no recovery path, directly mirroring the StWSX pattern where updating a core parameter after deployment strands user funds.

### Finding Description
`OmniBridge.sol` stores `nearBridgeDerivedAddress` as a mutable state variable and exposes it through a privileged setter:

```solidity
// OmniBridge.sol line 568-572
function setNearBridgeDerivedAddress(
    address nearBridgeDerivedAddress_
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
}
``` [1](#0-0) 

This address is the sole authority used to authenticate every inbound transfer finalization on the EVM side. In `finTransfer`, the contract recovers the signer from the MPC-generated ECDSA signature and compares it against the current value of `nearBridgeDerivedAddress`:

```solidity
// OmniBridge.sol line 311-313
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [2](#0-1) 

The same address is also used to authenticate `deployToken` calls: [3](#0-2) 

The NEAR→EVM transfer lifecycle is:
1. User calls `init_transfer` on NEAR; tokens are locked/burned on NEAR.
2. The NEAR MPC network signs the `TransferMessagePayload` with the key corresponding to the current `nearBridgeDerivedAddress`.
3. A relayer submits the signed payload to `finTransfer` on EVM.

If `setNearBridgeDerivedAddress` is called between steps 2 and 3 (or even between steps 1 and 2, since MPC signing is asynchronous), the signature produced by the old MPC key will not match the new `nearBridgeDerivedAddress`. The `finTransfer` call reverts. Because the nonce is only written before the revert and is rolled back, the nonce is not consumed — but the MPC signature is permanently bound to the old key. The NEAR side has no automatic refund mechanism for transfers whose EVM finalization fails due to a key mismatch; the tokens remain locked/burned on NEAR indefinitely.

`OmniBridgeWormhole.sol` has an analogous setter for the Wormhole contract address:

```solidity
// OmniBridgeWormhole.sol line 152-158
function setWormholeAddress(
    address wormholeAddress,
    uint8 consistencyLevel
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _wormhole = IWormhole(wormholeAddress);
    _consistencyLevel = consistencyLevel;
}
``` [4](#0-3) 

Updating `_wormhole` mid-flight causes `initTransfer` events to be published to a different Wormhole contract, breaking the VAA routing for any transfer whose event was already observed by Wormhole guardians on the old contract.

On the NEAR side, `add_prover`/`remove_prover` are similarly mutable post-deployment: [5](#0-4) 

Removing a prover while EVM→NEAR transfers are in-flight (proof already submitted, callback pending) causes those `fin_transfer` calls to fail with no refund path for the EVM-locked tokens.

### Impact Explanation
**Critical — Permanent freezing of bridged user funds.**

For every NEAR→EVM transfer in-flight at the moment `setNearBridgeDerivedAddress` is updated:
- Tokens are already locked/burned on NEAR (irreversible).
- The MPC signature is bound to the old key and cannot be re-generated for the same nonce without a new NEAR-side signing request.
- `finTransfer` on EVM permanently reverts for those payloads.
- Users lose their bridged assets with no on-chain recovery mechanism.

The same permanent-freeze impact applies to EVM→NEAR transfers if a prover is removed while their proof callbacks are pending.

### Likelihood Explanation
**Medium.** The setter is a legitimate operational function (e.g., MPC key rotation, security incident response). Any admin key rotation performed without first draining all in-flight transfers will silently strand those transfers. The window of vulnerability is the latency between NEAR-side lock and EVM-side finalization, which can span multiple blocks and is non-zero under normal bridge load. There is no on-chain guard (e.g., a transfer-count check or time-lock) preventing the update while transfers are pending.

### Recommendation
1. **Remove `setNearBridgeDerivedAddress` and `setWormholeAddress`** from `OmniBridge.sol` and `OmniBridgeWormhole.sol`, mirroring the resolution applied to StWSX: make these parameters immutable after deployment and perform any migration via a new contract deployment.
2. If mutability is required for operational reasons, add a **migration guard**: require that `pendingTransferCount == 0` (or enforce a time-lock with a public drain window) before allowing the parameter update, so users can complete or cancel in-flight transfers before the key changes.
3. Apply the same pattern to `add_prover`/`remove_prover` on the NEAR side: require no pending proofs for the affected chain before removal is permitted.

### Proof of Concept
1. Alice calls `init_transfer` on NEAR for 1000 USDC → EVM. NEAR locks 1000 USDC. MPC signs `TransferMessagePayload` with key `K_old`, producing signature `sig_old`. `nearBridgeDerivedAddress` = `addr(K_old)`.
2. Admin calls `setNearBridgeDerivedAddress(addr(K_new))`. Now `nearBridgeDerivedAddress` = `addr(K_new)`.
3. Relayer calls `OmniBridge.finTransfer(sig_old, payload)`.
4. `ECDSA.recover(hashed, sig_old)` returns `addr(K_old)` ≠ `addr(K_new)` → `revert InvalidSignature()`.
5. Alice's 1000 USDC remains locked on NEAR. There is no `refund` or `cancel` path on NEAR for a transfer whose EVM finalization has not been confirmed. Funds are permanently frozen. [1](#0-0) [6](#0-5) [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L149-153)
```text
        bytes32 hashed = keccak256(borshEncoded);

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

**File:** near/omni-bridge/src/lib.rs (L1749-1757)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_prover(&mut self, chain: ChainKind, account_id: AccountId) {
        self.provers.insert(&chain, &account_id);
    }

    #[access_control_any(roles(Role::DAO))]
    pub fn remove_prover(&mut self, chain: ChainKind) {
        self.provers.remove(&chain);
    }
```
