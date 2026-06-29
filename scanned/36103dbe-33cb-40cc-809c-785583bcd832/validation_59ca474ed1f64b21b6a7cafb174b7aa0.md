### Title
Non-Deterministic Bridge Token Address via `CREATE` Opcode Enables Token Metadata Binding Confusion on EVM Reorg - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.deployToken()` deploys bridge token proxies using the plain `CREATE` opcode (`new ERC1967Proxy(...)`), whose address is determined solely by the `OmniBridge` contract address and its nonce. This is non-deterministic with respect to the token identity. On EVM chains subject to reorgs (Polygon, Base, Arbitrum), two concurrent `deployToken` transactions can swap their deployed addresses after a reorg, causing the NEAR side's stored token binding to point to the wrong EVM token contract. Subsequent cross-chain transfers are then signed by MPC with the stale (wrong) token address, causing `finTransfer` to mint or transfer the wrong token to the recipient.

### Finding Description

In `OmniBridge.sol`, `deployToken` deploys each bridge token proxy using:

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

`new ERC1967Proxy(...)` uses the EVM `CREATE` opcode. The resulting address is `keccak256(rlp(OmniBridge_address, nonce))[12:]` — it depends on the OmniBridge contract's transaction nonce, not on the token identity (`metadata.token`). Two `deployToken` calls submitted in order A→B will produce addresses `addr_A` and `addr_B`. If a reorg reorders them to B→A, the addresses swap: token A gets `addr_B` and token B gets `addr_A`.

After deployment, the EVM mapping is updated atomically:

```solidity
isBridgeToken[address(bridgeTokenProxy)] = true;
ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
nearToEthToken[metadata.token] = address(bridgeTokenProxy);
``` [2](#0-1) 

The EVM mapping is self-consistent after the reorg. However, the NEAR side's binding is established via `bind_token_callback`, which reads the `DeployToken` event from the pre-reorg block (delivered via Wormhole VAA or light-client proof):

```rust
self.add_token(
    &deploy_token.token,
    &deploy_token.token_address,
    ...
);
``` [3](#0-2) 

If the Wormhole guardians or light client signed/accepted the pre-reorg `DeployToken` event before the reorg finalized, the NEAR side stores `tokenA.near → 0xADDR1`. After the reorg, EVM has `tokenA.near → 0xADDR2` and `tokenB.near → 0xADDR1`. The NEAR binding is now stale.

When `sign_transfer` is called for a NEAR→EVM transfer of `tokenA.near`, it looks up the stored token address:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    ...
``` [4](#0-3) 

This returns `0xADDR1` (stale). MPC signs a `TransferMessagePayload` with `token_address = 0xADDR1`. The relayer submits `finTransfer` to EVM with this payload. The EVM signature check passes (the signature is valid for `0xADDR1`). The EVM then checks `isBridgeToken[0xADDR1]` — which is `true` (it is Token B's address after the reorg) — and mints Token B to the recipient instead of Token A. [5](#0-4) 

**Contrast with Starknet**: The Starknet `deploy_token` uses a deterministic salt derived from the token ID hash, making the address stable regardless of transaction ordering:

```cairo
let salt: felt252 = token_id_hash.low.into();
let (contract_address, _) = deploy_syscall(
    self.bridge_token_class_hash.read(), salt, constructor_calldata.span(), false,
).unwrap_syscall();
``` [6](#0-5) 

The EVM implementation lacks this protection.

### Impact Explanation

A user transferring `tokenA.near` from NEAR to EVM receives Token B (a different, potentially worthless token) instead of Token A. Their Token A remains locked on NEAR with no recourse, since the `finTransfer` nonce is consumed. This constitutes permanent loss of bridged funds and unauthorized minting of the wrong token — both within the critical impact scope.

### Likelihood Explanation

Polygon (one of the supported EVM chains, deployed at `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`) has a documented history of multi-block reorgs. The attack window requires two `deployToken` transactions to be in-flight simultaneously and a reorg to reorder them before the NEAR side's binding is corrected. This is a narrow but realistic window on Polygon. The Wormhole guardian network signs VAAs after a configurable number of confirmations; if confirmations are insufficient relative to Polygon's reorg depth, the pre-reorg VAA can be accepted by NEAR while the EVM state has changed.

### Recommendation

Replace `new ERC1967Proxy(...)` with a `CREATE2`-based deployment using a salt derived from the token identifier (`metadata.token`), analogous to the Starknet implementation. This makes the deployed address deterministic and stable regardless of transaction ordering or reorgs:

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

This ensures that `tokenA.near` always maps to the same EVM address regardless of nonce or reorg, eliminating the binding confusion.

### Proof of Concept

1. Two `deployToken` transactions are submitted to Polygon mempool: Tx1 for `tokenA.near`, Tx2 for `tokenB.near`.
2. Tx1 is mined first (nonce N → `0xADDR1`), Tx2 second (nonce N+1 → `0xADDR2`).
3. Wormhole guardians observe the `DeployToken(0xADDR1, "tokenA.near")` event and issue a VAA.
4. NEAR relayer submits the VAA to `bind_token`; NEAR stores `tokenA.near → 0xADDR1`.
5. A Polygon reorg occurs, reordering Tx2 before Tx1: now `tokenB.near → 0xADDR1` (nonce N), `tokenA.near → 0xADDR2` (nonce N+1).
6. User initiates transfer of `tokenA.near` from NEAR to Polygon.
7. `sign_transfer` looks up `tokenA.near → 0xADDR1` (stale) and MPC signs `token_address = 0xADDR1`.
8. Relayer calls `finTransfer` on Polygon with `token_address = 0xADDR1`.
9. EVM: `isBridgeToken[0xADDR1] == true` (Token B). Token B is minted to the user.
10. User receives Token B instead of Token A; Token A is permanently locked on NEAR.

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-349)
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
```

**File:** near/omni-bridge/src/lib.rs (L462-469)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });
```

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** starknet/src/omni_bridge.cairo (L218-222)
```text
            let salt: felt252 = token_id_hash.low.into();
            let (contract_address, _) = deploy_syscall(
                self.bridge_token_class_hash.read(), salt, constructor_calldata.span(), false,
            )
                .unwrap_syscall();
```
