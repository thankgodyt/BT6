### Title
Non-Deterministic `CREATE` Opcode Used to Deploy `BridgeToken` Proxies on L2 Chains, Enabling Reorg-Induced Token Address Binding Corruption - (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.deployToken` deploys `ERC1967Proxy` instances using Solidity's `new` keyword, which compiles to the `CREATE` opcode. The resulting proxy address is a function of the deployer's nonce, not of the token's identity. On the L2 chains where OmniBridge is deployed (Arbitrum, Base, Polygon), a block reorganization can cause the same `deployToken` call to produce a different proxy address. This corrupts the canonical `nearToEthToken` / `isBridgeToken` binding that `finTransfer` and `initTransfer` depend on, permanently stranding bridged funds.

---

### Finding Description

In `OmniBridge.deployToken`, the bridge token proxy is created with:

```solidity
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
``` [1](#0-0) 

`new ERC1967Proxy(...)` emits the `CREATE` opcode. The resulting address is `keccak256(rlp(deployer, nonce))[12:]` — entirely dependent on the OmniBridge contract's deployment nonce at the moment of execution. The resulting address is then stored as the canonical binding:

```solidity
isBridgeToken[address(bridgeTokenProxy)] = true;
ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
nearToEthToken[metadata.token] = address(bridgeTokenProxy);
``` [2](#0-1) 

The contract is live on Arbitrum One, Base, and Polygon — all L2 chains with documented reorg risk. [3](#0-2) 

---

### Impact Explanation

**Scenario leading to permanent loss of bridged funds:**

1. **Block N**: A relayer calls `deployToken` for `wrap.near`. The OmniBridge's internal nonce is `X`, so the proxy deploys at address **A**. The `DeployToken` event is emitted with address A. The NEAR bridge records A as the canonical EVM address for `wrap.near`.

2. **Block N+1**: A user initiates a NEAR → EVM transfer. The NEAR MPC signs a `TransferMessagePayload` with `tokenAddress = A`. A relayer submits `finTransfer` on EVM. The check `isBridgeToken[A]` passes, tokens are minted to the user at address A.

3. **Reorg**: Blocks N and N+1 are reorganized. In the new Block N, an unrelated transaction executes first, consuming nonce `X`. When `deployToken` is re-executed, the nonce is now `X+1`, so the proxy deploys at address **B** ≠ A. `isBridgeToken[B] = true`; `isBridgeToken[A]` is never set.

4. **Re-submission**: The relayer re-submits the `finTransfer` with `tokenAddress = A`. The check `isBridgeToken[A]` is now **false**. Execution falls through to the `safeTransfer` branch:

```solidity
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
``` [4](#0-3) 

The OmniBridge holds no balance of token A (it was never locked there), so the call reverts. The user's NEAR-side tokens were already burned/locked. The `destinationNonce` is marked used in step 2's re-execution attempt, so the transfer cannot be retried. **Funds are permanently lost.**

Additionally, any user who received tokens at address A (if `finTransfer` was included before the reorg) now holds tokens at an address that `isBridgeToken` does not recognize. Their `initTransfer` call falls into the `safeTransferFrom` lock path instead of the `burn` path, meaning the bridge accumulates locked tokens it can never release back to NEAR. [5](#0-4) 

---

### Likelihood Explanation

- OmniBridge is deployed on Arbitrum One, Base, and Polygon — all L2 chains with known reorg exposure (Arbitrum and Base in particular have had documented reorgs).
- `deployToken` is callable by any address holding a valid MPC-signed metadata payload. The NEAR side issues these signatures permissionlessly as part of the normal token-registration flow, so the triggering transaction is not admin-gated.
- The attack window is the period between `deployToken` confirmation and NEAR-side finalization of the `DeployToken` event — a window that exists in every token deployment.

---

### Recommendation

Replace `new ERC1967Proxy(...)` with `new ERC1967Proxy{salt: ...}(...)` using `CREATE2` with a deterministic salt derived from the NEAR token identifier (e.g., `keccak256(abi.encodePacked(metadata.token))`). This makes the proxy address a pure function of the token identity, so a reorg that re-executes `deployToken` produces the same address regardless of nonce ordering.

```solidity
bytes32 salt = keccak256(abi.encodePacked(metadata.token));
address bridgeTokenProxy = address(
    new ERC1967Proxy{salt: salt}(
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

Note that the Starknet implementation already uses a deterministic salt derived from the token ID hash, demonstrating the correct pattern: [6](#0-5) 

---

### Proof of Concept

1. Deploy OmniBridge on a local fork of Base (which supports reorgs in testing).
2. Call `deployToken` with a valid MPC-signed metadata payload for `wrap.near`. Record the emitted proxy address **A** and the block number.
3. Simulate a reorg by rolling back one block and inserting a dummy transaction that increments the OmniBridge's nonce before `deployToken` re-executes.
4. Re-execute `deployToken` — observe that the proxy deploys at address **B** ≠ A, and `isBridgeToken[A]` is `false`.
5. Construct a `finTransfer` payload with `tokenAddress = A` and a valid MPC signature (obtained before the reorg). Submit it. Observe that the call reverts because `safeTransfer` of a non-existent token fails, while `completedTransfers[nonce]` is marked used, permanently blocking the transfer.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L161-172)
```text
        // slither-disable-next-line reentrancy-no-eth
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
```text
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

**File:** evm/.openzeppelin/arbitrum-one.json (L1-9)
```json
{
  "manifestVersion": "3.2",
  "proxies": [
    {
      "address": "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989",
      "txHash": "0x60b473ba8ae68fe192be3c960a3762e46099a3f9e60f60f7eed47db7c73ab29d",
      "kind": "uups"
    }
  ],
```

**File:** starknet/src/omni_bridge.cairo (L217-222)
```text
            // Use the low part of the u256 hash to ensure it fits in felt252
            let salt: felt252 = token_id_hash.low.into();
            let (contract_address, _) = deploy_syscall(
                self.bridge_token_class_hash.read(), salt, constructor_calldata.span(), false,
            )
                .unwrap_syscall();
```
