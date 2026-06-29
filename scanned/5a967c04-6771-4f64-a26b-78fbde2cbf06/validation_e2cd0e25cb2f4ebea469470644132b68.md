### Title
Missing Bridge Contract Address in `finTransfer` Signed Payload Hash Enables Cross-Instance Replay Attacks — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `finTransfer` function on EVM (and the analogous `fin_transfer` on Starknet) verifies an MPC-produced ECDSA signature over a Borsh-encoded payload that includes the destination chain ID (`omniBridgeChainId`) but **not** the bridge contract address. This is the direct analog of the reported `EntryPoint`-address-omission bug: just as omitting the `EntryPoint` address from the user-op hash allows replay across different `EntryPoint` instances on the same chain, omitting the bridge contract address allows replay across different bridge contract instances on the same chain that share the same `nearBridgeDerivedAddress` (MPC key).

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` constructs the hash to verify as:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),          // destination chain ID — present
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),          // recipient chain ID — present
    Borsh.encodeAddress(payload.recipient),
    ...
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [1](#0-0) 

The bridge contract address (`address(this)`) is **never** included in `borshEncoded`. The only domain-separation fields are `omniBridgeChainId` (chain ID) and `destinationNonce`. The nonce prevents replay on the **same** bridge instance, and the chain ID prevents replay **across chains**. But neither field prevents replay across **two different bridge contract instances on the same chain** that share the same `nearBridgeDerivedAddress` and `omniBridgeChainId`.

The NEAR side signs an identical payload via `sign_transfer` → `encode_hashable()`, which also does not include the destination bridge contract address: [2](#0-1) 

The Starknet `fin_transfer` has the same omission — `to_borsh(self.omni_bridge_chain_id.read())` encodes the chain ID but not the Starknet contract address: [3](#0-2) 

---

### Impact Explanation

**Critical — double-spending / unauthorized minting of bridged tokens.**

Attack scenario (bridge redeployment):

1. Bridge V1 is live on Ethereum (`nearBridgeDerivedAddress = X`, `omniBridgeChainId = 1`). Transfers with `destinationNonce` 1–N are finalized; V1's `completedTransfers[1..N] = true`.
2. The protocol deprecates V1 and deploys Bridge V2 at a new address on Ethereum, reusing the same MPC key (`nearBridgeDerivedAddress = X`) and the same `omniBridgeChainId = 1`. V2's `completedTransfers` mapping is empty.
3. An attacker replays any previously observed `finTransfer` calldata (valid MPC signature, nonce ≤ N) against V2.
4. V2 checks `completedTransfers[nonce] == false` (true, since V2 is fresh), verifies the signature (valid, same MPC key, same chain ID), and mints/unlocks tokens to the attacker.

The attacker receives tokens that were already disbursed on V1, constituting a double-spend. The same attack applies if two bridge variants (e.g., `OmniBridge` and `OmniBridgeWormhole`) are deployed on the same chain with the same `nearBridgeDerivedAddress`. [4](#0-3) 

---

### Likelihood Explanation

Bridge upgrades via new contract deployments (rather than transparent proxy upgrades) are a realistic operational event. The `.openzeppelin/` upgrade artifacts exist in the repo, but a non-proxy redeployment (e.g., after a critical bug fix or architecture change) would leave the new contract with an empty nonce bitmap. Additionally, the co-existence of `OmniBridge` and `OmniBridgeWormhole` on the same chain with a shared MPC key is a plausible configuration. An unprivileged attacker only needs to observe historical `finTransfer` transactions on-chain (fully public) and replay them — no private keys or admin access required. [5](#0-4) 

---

### Recommendation

Include the bridge contract address in the Borsh-encoded payload that is signed by the MPC network. On the EVM side, add `Borsh.encodeAddress(address(this))` (or an equivalent fixed contract identifier) to `borshEncoded` before hashing. The NEAR `sign_transfer` payload construction and all destination-chain verifiers (Starknet `to_borsh`, Solana `serialize_for_near`) must be updated consistently to include the destination bridge contract address, so that a signature produced for one contract instance is cryptographically bound to that instance and cannot be accepted by any other. [6](#0-5) [7](#0-6) [3](#0-2) 

---

### Proof of Concept

```
// Setup
Bridge V1 deployed at 0xAAAA on Ethereum (omniBridgeChainId=1, nearBridgeDerivedAddress=X)
Bridge V2 deployed at 0xBBBB on Ethereum (omniBridgeChainId=1, nearBridgeDerivedAddress=X)

// Step 1: Legitimate finTransfer on V1
// NEAR MPC signs payload: [TransferMessage | nonce=7 | originChain=Near | originNonce=42 |
//                          chainId=1 | token=0xUSDC | amount=1000 | chainId=1 | recipient=Alice | ...]
// Relayer calls V1.finTransfer(sig, payload) → V1.completedTransfers[7] = true, Alice gets 1000 USDC

// Step 2: Attacker replays identical calldata on V2
// V2.completedTransfers[7] == false  ← V2 is a fresh deployment
// keccak256(borshEncoded) is identical (same fields, no contract address)
// ECDSA.recover(hash, sig) == X == V2.nearBridgeDerivedAddress  ← passes
// V2 mints 1000 USDC to Alice (or attacker-controlled address)

// Result: 1000 USDC double-spent; bridge is insolvent by that amount
```

The attack requires only public on-chain data (the original `finTransfer` transaction) and a second bridge instance sharing the same MPC key — no privileged access needed.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L491-506)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );
```

**File:** starknet/src/omni_bridge.cairo (L252-254)
```text
            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```
