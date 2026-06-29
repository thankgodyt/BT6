### Title
`HyperliquedBridgeToken.mint(address,uint256,bytes)` Silently Redirects All Minted Tokens to `_systemAddress`, Causing Permanent Loss of Bridged Funds — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

---

### Summary

When `OmniBridge.finTransfer` is called with a payload where `message.length > 0` and `tokenAddress` points to a `HyperliquedBridgeToken`, the 3-arg `mint` override is invoked. That override first mints `value` tokens to `account`, then immediately transfers the entire `value` away from `account` to `_systemAddress`. The recipient ends with a zero balance; `_systemAddress` silently absorbs the full bridged amount.

---

### Finding Description

`OmniBridge.finTransfer` dispatches to the 3-arg `IBridgeToken.mint` whenever `isBridgeToken[payload.tokenAddress]` is true **and** `payload.message.length > 0`: [1](#0-0) 

The `HyperliquedBridgeToken` override of that 3-arg signature is:

```solidity
function mint(
    address account,
    uint256 value,
    bytes memory          // ← parameter is completely ignored
) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);
}
``` [2](#0-1) 

`_mint(account, value)` (OZ ERC-20) calls `_update(address(0), account, value)`, crediting `account` with `value`. The immediately following `_update(account, _systemAddress, value)` transfers that same `value` back out of `account` to `_systemAddress`. Net effect on `account`: **+value − value = 0**. `_systemAddress` receives the full amount.

The `bytes memory` argument — which carries `payload.message` — is never read; the routing to `_systemAddress` is unconditional.

The contract's own NatSpec confirms the two-path design:

> *2-arg mint(address, uint256): mints on HyperEVM (tokens go directly to user)*
> *3-arg mint(address, uint256, bytes): mints on HyperCore (includes _update to system address for spot-balance tracking)* [3](#0-2) 

The 3-arg path was designed for HyperCore spot-balance parking, but `OmniBridge` calls it for any inbound transfer that carries a non-empty message — a completely different semantic.

---

### Impact Explanation

Any inbound cross-chain transfer to a `HyperliquedBridgeToken` that includes a non-empty `message` field (e.g., a cross-chain DeFi call, a memo, or any bridge-level metadata) will:

1. Mint `payload.amount` tokens — increasing `totalSupply` correctly.
2. Immediately move all of those tokens to `_systemAddress`.
3. Leave `payload.recipient` with **zero tokens**.

The funds are not destroyed but are permanently inaccessible to the recipient; `_systemAddress` is the Hyperliquid system precompile address, not a user-controlled account. This constitutes a **permanent, irreversible loss of bridged funds** for every affected recipient.

---

### Likelihood Explanation

The trigger condition — `payload.message.length > 0` — is a standard, user-initiated feature of the bridge (cross-chain messaging, DeFi callbacks, memos). Any user on NEAR who initiates a transfer to a `HyperliquedBridgeToken` address with a non-empty message will have their funds lost upon finalization. No attacker capability beyond initiating a normal bridge transfer is required; a legitimate relayer submitting a legitimately signed payload is sufficient.

The NEAR bridge MPC key signs the full payload including the `message` field: [4](#0-3) 

A valid signature over a payload with `message.length > 0` is therefore obtainable through the normal bridge flow.

---

### Recommendation

The 3-arg `mint` in `HyperliquedBridgeToken` must not unconditionally redirect tokens to `_systemAddress`. Two options:

1. **Revert on direct bridge calls**: Override the 3-arg `mint` to revert, forcing all `finTransfer` paths through the 2-arg mint (i.e., always deliver tokens directly to the recipient on HyperEVM), and handle HyperCore parking exclusively through `coreReceiveWithData`.

2. **Decode the message to determine routing**: If the `bytes memory message` encodes a HyperCore-specific instruction, apply the `_systemAddress` redirect only when that instruction is present; otherwise fall through to a plain `_mint(account, value)`.

---

### Proof of Concept

```solidity
// 1. Deploy HyperliquedBridgeToken with a non-zero _systemAddress (e.g. address(0xSYS))
// 2. Register it in OmniBridge: isBridgeToken[token] = true
// 3. Obtain a valid nearBridgeDerivedAddress signature over a TransferMessagePayload
//    where payload.message = bytes("\x00")  (length == 1 > 0)
// 4. Call OmniBridge.finTransfer(sig, payload)
//    → isBridgeToken branch, message.length > 0
//    → IBridgeToken(token).mint(recipient, amount, "\x00")
//    → _mint(recipient, amount)          // recipient balance = amount
//    → _update(recipient, _systemAddress, amount)  // recipient balance = 0
// 5. Assert:
assert(token.balanceOf(recipient)      == 0);
assert(token.balanceOf(_systemAddress) == amount);
```

The `onlyOwner` guard on `mint` is satisfied because `OmniBridge` is the owner of the token (set during `initialize` via `__Ownable_init(_msgSender())`). [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L305-308)
```text
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
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

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L29-32)
```text
/// @notice Hyperliquid-specific BridgeToken with two mint paths:
/// - 2-arg mint(address, uint256): mints on HyperEVM (tokens go directly to user)
/// - 3-arg mint(address, uint256, bytes): mints on HyperCore (includes _update to system address for spot-balance tracking)
contract HyperliquedBridgeToken is BridgeToken, ICoreReceiveWithData {
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L53-74)
```text
    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address systemAddress_,
        address hyperCoreDeployer_
    ) external initializer {
        __ERC20_init(name_, symbol_);
        __UUPSUpgradeable_init();
        __Ownable_init(_msgSender());

        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _systemAddress = systemAddress_;

        bytes32 hyperCoreDeployerSlot = HYPER_CORE_DEPLOYER_SLOT;
        assembly {
            sstore(hyperCoreDeployerSlot, hyperCoreDeployer_)
        }
        emit HyperCoreDeployerSet(hyperCoreDeployer_);
    }
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L76-83)
```text
    function mint(
        address account,
        uint256 value,
        bytes memory
    ) external override onlyOwner {
        _mint(account, value);
        _update(account, _systemAddress, value);
    }
```
