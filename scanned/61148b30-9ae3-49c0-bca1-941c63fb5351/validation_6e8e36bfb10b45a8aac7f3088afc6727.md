### Title
Unpermissioned `logMetadata` Allows Any User to Deploy Counterfeit Tokens with Arbitrary Name/Symbol on NEAR - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.logMetadata(address tokenAddress)` is callable by any unprivileged user with any ERC-20 address. Because the emitter of the resulting `LogMetadata` event is the OmniBridge contract itself (a registered factory), the NEAR bridge accepts the proof and deploys a new NEP-141 token whose name, symbol, and decimals are fully attacker-controlled. This enables an attacker to deploy a counterfeit token on NEAR that impersonates any legitimate token (e.g., USDC, USDT, WBTC) before the real token is bridged, causing token metadata binding confusion and enabling financial loss for users who trade based on name/symbol.

### Finding Description

`OmniBridge.logMetadata` contains no access control and no validation of the supplied token address:

```solidity
function logMetadata(address tokenAddress) external payable {
    string memory name = IERC20Metadata(tokenAddress).name();
    string memory symbol = IERC20Metadata(tokenAddress).symbol();
    uint8 decimals = IERC20Metadata(tokenAddress).decimals();
    logMetadataExtension(tokenAddress, name, symbol, decimals);
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [1](#0-0) 

The emitter of the `LogMetadata` event is the OmniBridge contract itself. On the NEAR side, `deploy_token_callback` validates only that the emitter address matches a registered factory:

```rust
require!(
    self.factories.get(&chain) == Some(metadata.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [2](#0-1) 

Since the OmniBridge contract IS the registered factory, this check always passes for any `logMetadata` call. The name, symbol, and decimals from the attacker-controlled ERC-20 are passed directly into `deploy_token_internal` and stored in the deployed NEP-141 token's metadata:

```rust
self.deploy_token_internal(
    chain,
    &metadata.token_address,
    BasicMetadata {
        name: metadata.name,
        symbol: metadata.symbol,
        decimals: metadata.decimals,
    },
    attached_deposit,
)
``` [3](#0-2) 

The `LogMetadataMessage` struct carries name/symbol/decimals verbatim from the event with no sanitization: [4](#0-3) 

The NEAR token's metadata is then set via `set_metadata` in `OmniToken`, which accepts any string values: [5](#0-4) 

### Impact Explanation

An attacker can deploy a fake ERC-20 on Ethereum with `name() = "USD Coin"`, `symbol() = "USDC"`, `decimals() = 6`, then call `logMetadata(fakeUSDCAddress)`. A relayer processes the event and calls `deploy_token` on NEAR, resulting in a NEP-141 token with account ID `<fake_addr_hex>.omdep.near` but with `ft_metadata()` returning `name: "USD Coin", symbol: "USDC", decimals: 6`. This token is indistinguishable from real bridged USDC by name/symbol in any wallet, DEX UI, or DeFi protocol that identifies tokens by metadata rather than account ID. Users who receive or trade this token suffer direct financial loss. Additionally, if the attacker pre-registers the fake token before the real USDC is ever bridged, the real USDC will receive a different NEAR account ID, creating permanent ecosystem confusion.

A secondary variant uses decimal manipulation: a fake token with `decimals() = 18` but `symbol() = "USDC"` causes DeFi protocols that read `ft_metadata().decimals` to miscalculate token values by a factor of 10^12.

### Likelihood Explanation

The attack requires only: (1) deploying a cheap ERC-20 contract on Ethereum, (2) calling `logMetadata` (permissionless, costs only gas), and (3) waiting for a relayer to process the event (relayers are automated). No privileged access, no key compromise, and no social engineering of the bridge operators is required. The attack is fully executable by any on-chain actor.

### Recommendation

Add a token allowlist or require that `logMetadata` can only be called for tokens that have been explicitly registered (e.g., via `addCustomToken` or a separate admin-gated allowlist). Alternatively, restrict `logMetadata` to `onlyRole(DEFAULT_ADMIN_ROLE)` or a dedicated `METADATA_LOGGER_ROLE`, consistent with how `setMetadata` is already gated: [6](#0-5) 

### Proof of Concept

1. Attacker deploys `FakeUSDC` on Ethereum:
   ```solidity
   contract FakeUSDC {
       function name() external pure returns (string memory) { return "USD Coin"; }
       function symbol() external pure returns (string memory) { return "USDC"; }
       function decimals() external pure returns (uint8) { return 6; }
   }
   ```

2. Attacker calls (no special role required):
   ```solidity
   OmniBridge(bridgeAddress).logMetadata(address(fakeUSDC));
   ```
   This emits `LogMetadata(fakeUSDCAddress, "USD Coin", "USDC", 6)` from the OmniBridge contract.

3. Relayer observes the event, constructs a `LogMetadataMessage` with `emitter_address = OmniBridgeAddress` (a registered factory), and calls `deploy_token` on NEAR. [7](#0-6) 

4. NEAR's `deploy_token_callback` passes the factory check and deploys a NEP-141 token at e.g. `<fake_addr_hex>.omdep.near` with `ft_metadata()` returning `{ name: "USD Coin", symbol: "USDC", decimals: 6 }`. [8](#0-7) 

5. Attacker mints `FakeUSDC` tokens to themselves, bridges them to NEAR via `initTransfer`, and sells the resulting NEAR-side "USDC" tokens on a DEX to users who identify the token by its name/symbol. Victims receive worthless tokens in exchange for real value.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L204-208)
```text
    function setMetadata(
        string calldata token,
        string calldata name,
        string calldata symbol
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
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

**File:** near/omni-bridge/src/lib.rs (L1155-1174)
```rust
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
```

**File:** near/omni-types/src/prover_result.rs (L39-47)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct LogMetadataMessage {
    pub token_address: OmniAddress,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub emitter_address: OmniAddress,
}
```

**File:** near/omni-token/src/lib.rs (L156-188)
```rust
    fn set_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    ) {
        self.assert_controller();

        let mut metadata = self.ft_metadata();
        if let Some(name) = name {
            metadata.name = name;
        }
        if let Some(symbol) = symbol {
            metadata.symbol = symbol;
        }
        if let Some(reference) = reference {
            metadata.reference = Some(reference);
        }
        if let Some(reference_hash) = reference_hash {
            metadata.reference_hash = Some(reference_hash);
        }
        if let Some(decimals) = decimals {
            metadata.decimals = decimals;
        }
        if let Some(icon) = icon {
            metadata.icon = Some(icon);
        }

        self.metadata.set(&metadata);
    }
```

**File:** near/omni-types/src/evm/events.rs (L158-176)
```rust
impl TryFromLog<Log<LogMetadata>> for LogMetadataMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<LogMetadata>) -> Result<Self, Self::Error> {
        Ok(Self {
            token_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.data.tokenAddress.into()),
            )?,
            name: event.data.name,
            symbol: event.data.symbol,
            decimals: event.data.decimals,

            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
        })
    }
```
