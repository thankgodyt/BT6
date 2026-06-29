### Title
`logMetadata` and `logMetadata1155` Bypass `PAUSED_DEPLOY_TOKEN` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` defines three selective pause flags. `pauseAll()` sets all three, including `PAUSED_DEPLOY_TOKEN`, to block token deployment. However, `logMetadata` and `logMetadata1155` carry no `whenNotPaused` guard. In the deployed `OmniBridgeWormhole` variant, these functions publish Wormhole VAAs of type `LogMetadata` that the NEAR bridge's `deploy_token` consumes to deploy tokens on NEAR — executing a deployer-equivalent bridge action while the EVM side is paused.

### Finding Description
`OmniBridge.sol` exposes three pause flags and a `pauseAll()` helper:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;

function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
    uint256 flags = PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER | PAUSED_DEPLOY_TOKEN;
    _pause(flags);
}
``` [1](#0-0) 

`deployToken` is correctly gated:

```solidity
function deployToken(...) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
``` [2](#0-1) 

But `logMetadata` and `logMetadata1155` carry **no pause modifier**:

```solidity
function logMetadata(address tokenAddress) external payable {
    ...
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}

function logMetadata1155(address tokenAddress, uint256 tokenId) external payable {
    ...
    emit BridgeTypes.LogMetadata(...);
}
``` [3](#0-2) 

In `OmniBridgeWormhole`, `logMetadataExtension` is overridden to publish a live Wormhole message:

```solidity
function logMetadataExtension(...) internal override {
    bytes memory payload = bytes.concat(
        bytes1(uint8(MessageType.LogMetadata)), ...
    );
    _wormhole.publishMessage{value: msg.value}(wormholeNonce, payload, _consistencyLevel);
    wormholeNonce++;
}
``` [4](#0-3) 

The resulting Wormhole VAA is the exact input consumed by the NEAR bridge's `deploy_token` to deploy a bridged token on NEAR:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
    self.verify_proof(args.chain_kind, args.prover_args)...
}
``` [5](#0-4) 

### Impact Explanation
When an operator calls `pauseAll()` on the EVM bridge (e.g., in response to a security incident), the intent is to halt all bridge operations including token deployment. Because `logMetadata` and `logMetadata1155` are unguarded, any unprivileged caller can still publish a `LogMetadata` Wormhole VAA. If the NEAR bridge is not simultaneously paused, a relayer can immediately submit that VAA to `deploy_token` on NEAR, completing a token deployment that the EVM-side pause was meant to prevent. This is a pause bypass that lets an attacker execute deployer-equivalent bridge actions.

### Likelihood Explanation
High. `logMetadata` is a public, payable function with no access control and no pause check. Any EOA can call it with any ERC-20 address while the EVM bridge is paused. The Wormhole message is published atomically in the same transaction. The only mitigating factor is that the NEAR bridge must also be unpaused for the VAA to be finalized there; operators who pause both sides simultaneously are not affected.

### Recommendation
Add `whenNotPaused(PAUSED_DEPLOY_TOKEN)` to both `logMetadata` and `logMetadata1155` in `OmniBridge.sol`, consistent with how `deployToken` is guarded:

```solidity
function logMetadata(address tokenAddress) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) {
function logMetadata1155(address tokenAddress, uint256 tokenId) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) {
```

### Proof of Concept
1. Operator detects an incident and calls `OmniBridge.pauseAll()` on the EVM deployment of `OmniBridgeWormhole`. `PAUSED_DEPLOY_TOKEN` is now set; `deployToken` reverts.
2. Attacker calls `OmniBridgeWormhole.logMetadata(victimToken)` with `msg.value >= wormhole.messageFee()`.
3. `logMetadataExtension` executes without revert, publishes a Wormhole VAA encoding `MessageType.LogMetadata` for `victimToken`, and increments `wormholeNonce`.
4. A relayer (or the attacker acting as relayer) submits the VAA to the NEAR bridge's `deploy_token`. If NEAR is not paused, `deploy_token_callback` deploys the token on NEAR, completing a deployer action that the EVM pause was intended to block. [6](#0-5) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L52-57)
```text
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;

    error InvalidSignature();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-270)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }

    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-557)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L72-94)
```text
    function logMetadataExtension(
        address tokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.LogMetadata)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeString(name),
            Borsh.encodeString(symbol),
            bytes1(decimals)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** near/omni-bridge/src/lib.rs (L1137-1145)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(NO_DEPOSIT)
                .with_static_gas(DEPLOY_TOKEN_CALLBACK_GAS)
                .deploy_token_callback(near_sdk::env::attached_deposit()),
        )
    }
```
