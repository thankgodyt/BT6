### Title
ERC777 `tokensToSend` Hook Reentrancy in `initTransfer` Causes Nonce Collision and Permanent Freezing of Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::initTransfer` increments `currentOriginNonce` before the external token transfer call, but reads the storage variable **again** after the external call when passing it to `initTransferExtension` and `emit`. An ERC777 token's `tokensToSend` hook can reenter `initTransfer` during the `safeTransferFrom` call, causing both the inner and outer invocations to emit `InitTransfer` events with the **same** `originNonce`. Because NEAR uses `(origin_chain, origin_nonce)` as a unique transfer ID, only one of the two transfers can ever be finalized; the other transfer's tokens are permanently frozen in the bridge.

---

### Finding Description

In `initTransfer` (lines 381–436 of `OmniBridge.sol`):

```solidity
currentOriginNonce += 1;          // ① nonce incremented to N+1
// ...
IERC20(tokenAddress).safeTransferFrom(   // ② ERC777 tokensToSend hook fires here
    msg.sender, address(this), amount
);
// ...
initTransferExtension(
    msg.sender, tokenAddress,
    currentOriginNonce,            // ③ reads storage — may now be N+2
    ...
);
emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress,
    currentOriginNonce,            // ④ reads storage — may now be N+2
    ...
);
``` [1](#0-0) 

The nonce is captured in a storage write at step ①, but steps ③ and ④ re-read the storage variable rather than using a local snapshot. There is no `ReentrancyGuard` or `nonReentrant` modifier anywhere in the contract. [2](#0-1) 

The CLAUDE.md documents "State before external calls" as the **primary reentrancy defense**, but this defense is incomplete: the nonce is written before the external call yet consumed (for event emission) after it. [3](#0-2) 

ERC777 tokens implement ERC20 compatibility; `safeTransferFrom` triggers the `tokensToSend` hook on the sender's ERC1820-registered implementer. `logMetadata` is **permissionless**, so any ERC777 token can be registered with the bridge by anyone. [4](#0-3) 

---

### Impact Explanation

**Attack sequence:**

1. Attacker calls `initTransfer(erc777Token, A1, ...)` — `currentOriginNonce` becomes N+1.
2. During `safeTransferFrom`, the ERC777 `tokensToSend` hook fires on the attacker's contract.
3. Attacker reenters `initTransfer(erc777Token, A2, ...)` — `currentOriginNonce` becomes N+2; inner call transfers A2 tokens and emits `InitTransfer` with nonce **N+2**.
4. Outer call resumes; A1 tokens are transferred; `initTransferExtension` and `emit` read `currentOriginNonce` = **N+2** again — outer call also emits `InitTransfer` with nonce **N+2**.

Result: two on-chain `InitTransfer` events share nonce N+2; nonce N+1 is skipped. The NEAR bridge contract uses `(origin_chain, origin_nonce)` as a unique transfer ID: [5](#0-4) 

Only one of the two N+2 events can be finalized on NEAR. The other transfer's tokens (A1 or A2) are permanently frozen in the bridge with no recovery path. This satisfies the "permanent freezing of bridged funds" impact criterion.

---

### Likelihood Explanation

**Low.** The attacker must use an ERC777 token registered with the bridge (achievable permissionlessly via `logMetadata`), register an ERC1820 implementer for their address, and accept that they will permanently lose their own tokens in the process. There is no direct profit motive, making deliberate exploitation unlikely but not impossible (e.g., griefing the protocol's accounting invariants or causing a targeted fund freeze).

---

### Recommendation

Capture `currentOriginNonce` in a local variable **before** any external call and use only that local variable in `initTransferExtension` and `emit`:

```solidity
currentOriginNonce += 1;
uint64 nonce = currentOriginNonce;   // snapshot before external call
// ... token transfer ...
initTransferExtension(..., nonce, ...);
emit BridgeTypes.InitTransfer(..., nonce, ...);
```

Alternatively, add OpenZeppelin's `ReentrancyGuardUpgradeable` and apply `nonReentrant` to `initTransfer` and `initTransfer1155`.

---

### Proof of Concept

```
Attacker contract implements IERC777Sender (registered via ERC1820):

tokensToSend(...) {
    // Reenter with a dust amount to "claim" nonce N+2
    OmniBridge.initTransfer(erc777Token, 1, 0, 0, "attacker.near", "");
}

Attack:
1. OmniBridge.initTransfer(erc777Token, 1_000e18, 0, 0, "attacker.near", "")
   → currentOriginNonce = N+1
   → safeTransferFrom triggers tokensToSend hook
       → reentrant initTransfer(erc777Token, 1, ...)
           → currentOriginNonce = N+2
           → 1 token transferred
           → emit InitTransfer(nonce=N+2, amount=1)
   → outer safeTransferFrom completes; 1_000e18 tokens transferred
   → emit InitTransfer(nonce=N+2, amount=1_000e18)   ← COLLISION

2. Relayer submits proof of (nonce=N+2, amount=1) → NEAR mints 1 token.
3. Relayer submits proof of (nonce=N+2, amount=1_000e18) → NEAR rejects as replay.
4. 1_000e18 tokens are permanently locked in OmniBridge with no recovery path.
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L28-55)
```text
contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;

    mapping(address => string) public ethToNearToken;
    mapping(string => address) public nearToEthToken;
    mapping(address => bool) public isBridgeToken;

    address public tokenImplementationAddress;
    address public nearBridgeDerivedAddress;
    uint8 public omniBridgeChainId;

    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;

    mapping(address => address) public customMinters;
    mapping(address => MultiTokenInfo) public multiTokens;

    bytes32 public constant PAUSABLE_ADMIN_ROLE =
        keccak256("PAUSABLE_ADMIN_ROLE");
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L381-436)
```text
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
