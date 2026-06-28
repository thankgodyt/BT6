### Title
Malicious ERC-20 Passed to `initTransfer` Bypasses Actual Token Custody, Enabling Unauthorized NEAR-Side Minting — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `initTransfer` accepts any caller-supplied `tokenAddress` and calls `safeTransferFrom` on it without checking the bridge's actual token balance before and after the call. A malicious ERC-20 that returns `true` from `transferFrom` without moving any tokens causes the bridge to emit a fully-formed `InitTransfer` event. Because the NEAR hub trusts the on-chain proof of that event, it mints the claimed amount of the corresponding NEAR token to the attacker — with zero real collateral deposited.

---

### Finding Description

`initTransfer` in `OmniBridge.sol` handles non-bridge, non-custom-minter tokens with:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
``` [1](#0-0) 

OpenZeppelin's `SafeERC20.safeTransferFrom` only checks that the call did not revert and that any returned boolean is `true`. It does **not** verify that `address(this)`'s balance actually increased by `amount`. A malicious token contract can satisfy both conditions while transferring nothing.

After the (fake) transfer, the function unconditionally emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress, currentOriginNonce,
    amount, fee, nativeFee, recipient, message
);
``` [2](#0-1) 

This event is emitted by `OmniBridge` itself — the address registered as the factory on the NEAR hub. The NEAR `fin_transfer_callback` validates only that the emitter matches the registered factory and that the token has known decimals:

```rust
require!(
    self.factories.get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
let decimals = self.token_decimals.get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
``` [3](#0-2) 

Both checks pass once the malicious token is registered (see attack steps below). The NEAR bridge then mints the full claimed `amount` to the attacker.

The permissionless `logMetadata` function is the prerequisite that lets the attacker register the malicious token:

```solidity
function logMetadata(address tokenAddress) external payable {
    string memory name  = IERC20Metadata(tokenAddress).name();
    string memory symbol = IERC20Metadata(tokenAddress).symbol();
    uint8  decimals = IERC20Metadata(tokenAddress).decimals();
    logMetadataExtension(tokenAddress, name, symbol, decimals);
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [4](#0-3) 

No access control, no whitelist check. Any address can be passed.

---

### Impact Explanation

An attacker can mint an unbounded quantity of a NEAR-side bridged token without depositing any EVM-side collateral. This is unauthorized minting — a critical impact under the allowed scope. If the minted token is listed on a DEX, used as collateral in a lending protocol, or exchanged peer-to-peer, the attacker extracts real value while the bridge's escrow accounting is permanently inflated relative to actual custody.

---

### Likelihood Explanation

Both prerequisite steps (`logMetadata` and `initTransfer`) are permissionless public functions callable by any EOA. No admin key, no privileged role, no front-running dependency, and no special on-chain state is required beyond deploying a ~20-line malicious ERC-20. The attack is fully self-contained and repeatable.

---

### Proof of Concept

1. **Deploy malicious ERC-20** — `transferFrom` always returns `true` without moving tokens; `name()`, `symbol()`, `decimals()` return valid non-empty strings.

2. **Register the token** — Call `OmniBridge.logMetadata(maliciousToken)`. The `LogMetadata` event is emitted from the registered factory address. [4](#0-3) 

3. **Deploy on NEAR** — Submit the EVM proof to `deploy_token` on the NEAR hub. `deploy_token_callback` verifies the emitter is the registered factory and calls `deploy_token_internal`, creating a new NEAR token mapped to `maliciousToken`. [5](#0-4) 

4. **Fake deposit** — Call `OmniBridge.initTransfer(maliciousToken, 1_000_000_000_000, 0, 0, "near:attacker.near", "")`. `safeTransferFrom` returns `true` without transferring. `InitTransfer` is emitted with `amount = 1_000_000_000_000`. [6](#0-5) 

5. **Claim on NEAR** — Submit the EVM proof to `fin_transfer`. `fin_transfer_callback` passes both the factory check and the decimals lookup, then mints `1_000_000_000_000` of the NEAR token to `attacker.near`. [7](#0-6) 

Steps 4–5 can be repeated indefinitely with increasing amounts.

---

### Recommendation

In `initTransfer`, record the bridge's token balance **before** calling `safeTransferFrom` and assert it increased by at least `amount` **after**:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 balanceAfter  = IERC20(tokenAddress).balanceOf(address(this));
require(balanceAfter - balanceBefore >= amount, "Transfer amount mismatch");
```

This mirrors the mitigation recommended in M-02 and correctly handles fee-on-transfer tokens as well as malicious tokens that return `true` without transferring. Optionally, add a token allowlist so only pre-approved ERC-20 addresses can be used in `initTransfer`, eliminating the malicious-token registration vector through `logMetadata` entirely.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-436)
```text
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

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
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
