### Title
Unvalidated Token Name/Symbol in `logMetadata` Pipeline Enables Fake Bridged-Token Deployment - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
The `logMetadata` function on EVM `OmniBridge` is public and permissionless. It reads `name`, `symbol`, and `decimals` directly from any caller-supplied token contract and forwards them through the Wormhole pipeline to NEAR, where they are used verbatim to deploy a new `OmniToken`. No step in the pipeline validates the content of the name or symbol strings. An attacker can deploy an EVM token with `name = "USD Coin"` and `symbol = "USDC"`, call `logMetadata`, and cause the official bridge to deploy a NEAR token that is indistinguishable from real USDC in every wallet and DEX interface.

### Finding Description

**Step 1 — Permissionless entry point on EVM.**

`logMetadata` in `OmniBridge.sol` accepts any `tokenAddress` with no access control and no content validation on the returned strings:

```solidity
function logMetadata(address tokenAddress) external payable {
    string memory name    = IERC20Metadata(tokenAddress).name();
    string memory symbol  = IERC20Metadata(tokenAddress).symbol();
    uint8  decimals       = IERC20Metadata(tokenAddress).decimals();
    logMetadataExtension(tokenAddress, name, symbol, decimals);
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [1](#0-0) 

**Step 2 — Name/symbol forwarded verbatim into Wormhole.**

`OmniBridgeWormhole.logMetadataExtension` serialises the raw strings into a Wormhole message with no sanitisation: [2](#0-1) 

**Step 3 — Wormhole prover proxy passes strings through without validation.**

`ParsedVAA::try_into::<LogMetadataMessage>` copies `name` and `symbol` from the VAA payload directly into the `LogMetadataMessage` struct: [3](#0-2) 

**Step 4 — NEAR `deploy_token_callback` performs no name/symbol check.**

The only guard in `deploy_token_callback` is that the emitter address matches a registered factory. The `name` and `symbol` fields are passed directly to `deploy_token_internal`:

```rust
self.deploy_token_internal(
    chain,
    &metadata.token_address,
    BasicMetadata {
        name: metadata.name,    // ← unvalidated
        symbol: metadata.symbol, // ← unvalidated
        decimals: metadata.decimals,
    },
    attached_deposit,
)
``` [4](#0-3) 

**Contrast with the NEAR → EVM direction**, where `log_metadata_callback` at least checks non-emptiness: [5](#0-4) 
Even that check is absent in the EVM → NEAR direction.

**Step 5 — `deploy_token_internal` deploys the OmniToken with the attacker-supplied strings.** [6](#0-5) 

### Impact Explanation

An attacker deploys a NEAR `OmniToken` through the official bridge infrastructure whose on-chain `name` and `symbol` are identical to a high-value token (USDC, USDT, WETH, etc.). The token's NEAR account ID is derived from the attacker's EVM address, so it is a different account from the real token, but every wallet, block explorer, and DEX that displays tokens by `name`/`symbol` will show it as indistinguishable from the real asset. Users who receive this token (e.g., as the output of a DEX swap that routes by symbol) lose real funds. This is a direct token metadata binding confusion attack that changes user balances.

### Likelihood Explanation

Likelihood is **high**. `logMetadata` is intentionally public and permissionless (confirmed by `starknet/CLAUDE.md`: *"Public `log_metadata`: Intentionally permissionless for token discovery"*). The only cost to the attacker is gas to deploy a fake EVM token and call `logMetadata`. No privileged access, no key compromise, and no social engineering of bridge operators is required — the bridge's own normal execution path performs the deployment. [7](#0-6) 

### Recommendation

1. **Short term:** In `deploy_token_callback` on NEAR, reject deployments where `metadata.name` or `metadata.symbol` duplicates the name or symbol of any already-registered token. Alternatively, append the origin chain and a truncated token address to the name/symbol (e.g., `"USD Coin (eth:0xA0b8…)"`) so the bridged representation is always distinguishable from the canonical asset.

2. **Long term:** Maintain an on-chain allowlist of `(token_address, expected_name, expected_symbol)` tuples that the bridge operator controls. `logMetadata` should verify the submitted token address is on the allowlist before forwarding metadata. This eliminates the ability for arbitrary token deployers to inject misleading metadata into the bridge's deployment pipeline.

### Proof of Concept

```
1. Attacker deploys FakeUSDC on Ethereum:
      name()     → "USD Coin"
      symbol()   → "USDC"
      decimals() → 6

2. Attacker calls:
      OmniBridgeWormhole.logMetadata(FakeUSDC_address)
      // No access control. Emits LogMetadata("USD Coin","USDC",6) + Wormhole VAA.

3. Wormhole guardians attest the VAA.

4. Relayer (or attacker) calls NEAR omni-bridge:
      deploy_token({ chain_kind: Eth, prover_args: <wormhole_vaa> })

5. deploy_token_callback verifies emitter == registered Ethereum factory ✓
   Calls deploy_token_internal with name="USD Coin", symbol="USDC".

6. A new OmniToken is deployed at, e.g.:
      eth-<attacker_addr_hex>.omdep.near
   with ft_metadata() returning name="USD Coin", symbol="USDC".

7. Any NEAR wallet or DEX querying ft_metadata() displays this token
   as "USD Coin (USDC)", identical to the real bridged USDC.
   Users who receive or swap into this token lose real funds.
```

### Citations

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

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L230-248)
```rust
impl TryInto<LogMetadataMessage> for ParsedVAA {
    type Error = String;

    fn try_into(self) -> Result<LogMetadataMessage, String> {
        let parsed_payload: LogMetadataWh = borsh::from_slice(&self.payload).map_err(stringify)?;

        if parsed_payload.payload_type != ProofKind::LogMetadata {
            return Err("Invalid proof kind".to_owned());
        }

        let chain_kind = parsed_payload.token_address.get_chain();
        Ok(LogMetadataMessage {
            token_address: parsed_payload.token_address,
            name: parsed_payload.name,
            symbol: parsed_payload.symbol,
            decimals: parsed_payload.decimals,
            emitter_address: OmniAddress::new_from_slice(chain_kind, &self.emitter_address)?,
        })
    }
```

**File:** near/omni-bridge/src/lib.rs (L336-339)
```rust
        require!(
            !metadata.name.is_empty() && !metadata.symbol.is_empty(),
            BridgeError::InvalidMetadata.as_ref()
        );
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

**File:** near/omni-bridge/src/lib.rs (L2446-2453)
```rust
        ext_deployer::ext(deployer)
            .with_static_gas(DEPLOY_TOKEN_GAS)
            .with_attached_deposit(attached_deposit.saturating_sub(required_deposit))
            .deploy_token(token_id.clone(), metadata)
            .then(
                Self::ext(env::current_account_id())
                    .deploy_token_by_deployer_callback(token_address, token_id),
            )
```

**File:** starknet/CLAUDE.md (L46-46)
```markdown
2. **Public `log_metadata`**: Intentionally permissionless for token discovery
```
