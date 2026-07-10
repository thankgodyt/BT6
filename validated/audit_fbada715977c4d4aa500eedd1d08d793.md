### Title
Unprotected `new()` Initialization Allows Any Caller to Seize `bridge_id` and Mint Unlimited nBTC - (File: contracts/nbtc/src/lib.rs)

---

### Summary
The `nbtc` token contract's `new()` initializer is a public function with no caller restriction. Any NEAR account that calls it before the legitimate deployer can set an arbitrary `bridge_id`, which is the sole account authorized to call `mint()` and `burn()`. An attacker who wins this race becomes the exclusive minter of nBTC.

---

### Finding Description

`contracts/nbtc/src/lib.rs` defines the nBTC NEP-141 token contract. Its initializer is:

```rust
#[init]
pub fn new(
    controller: AccountId,
    bridge_id: AccountId,
    name: String,
    symbol: String,
    icon: Option<String>,
    decimals: u8,
) -> Self {
    require!(!env::state_exists(), "Already initialized");
    ...
    Self { controller, bridge_id, token, metadata }
}
```

The only guard is `require!(!env::state_exists(), ...)`. There is no check that `env::predecessor_account_id() == env::current_account_id()` or any other caller restriction. The `#[init]` attribute in NEAR SDK does not restrict who may call the function — it only prevents calling it after state already exists.

The two fields set by `new()` are the root of all privilege in the contract:

- `bridge_id` — the only account allowed to call `mint()` and `burn()`:
  ```rust
  fn assert_bridge(&self) {
      require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
  }
  ```
- `controller` — the only account allowed to call `set_controller`, `set_metadata`, `upgrade_and_migrate`, and `attach_full_access_key`.

In NEAR, contract deployment and initialization are separate transactions. The deployer first deploys the WASM (creating the contract account), then calls `new()` in a subsequent transaction. This creates a window — however brief — during which any NEAR account can call `new()` with attacker-controlled `controller` and `bridge_id` values. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

If an attacker calls `new()` first and supplies their own account as `bridge_id`, they become the exclusive authorized caller of `mint()`. `mint()` calls `mint_inner()` which calls `internal_deposit()` with no supply cap:

```rust
pub fn mint(
    &mut self,
    mint_account_id: AccountId,
    mint_amount: U128,
    ...
) {
    self.assert_bridge();
    self.mint_inner(&mint_account_id, mint_amount);
    ...
}
```

The attacker can mint an unbounded quantity of nBTC to any registered account. This constitutes **unauthorized minting of nBTC** — a Critical impact under the allowed scope. Additionally, the attacker-controlled `controller` can call `upgrade_and_migrate` to deploy arbitrary replacement code, permanently destroying the contract. [4](#0-3) [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The attack requires the attacker to observe the nBTC contract account being created (or the WASM being deployed) and submit a `new()` call before the legitimate deployer does. In NEAR, transactions within a shard are ordered deterministically, so this is a race rather than a gas-price auction. The attacker must monitor the NEAR chain for the contract account creation event and submit their `new()` call in the same or next block. This is operationally feasible for a motivated attacker watching the chain, especially during a known deployment event (e.g., a DAO-approved upgrade proposal). The deployment scripts confirm that deployment and initialization are separate steps. [7](#0-6) [8](#0-7) 

---

### Recommendation

**Short term:** Enforce that `new()` can only be called by the contract account itself (i.e., the deployer who holds the full-access key to the account):

```rust
require!(
    env::predecessor_account_id() == env::current_account_id(),
    "Only the contract account may initialize"
);
```

**Long term:** Deploy and initialize in a single atomic batch transaction so no window exists between code deployment and state initialization. This is the standard safe pattern in NEAR and eliminates the race entirely.

---

### Proof of Concept

1. Attacker monitors the NEAR chain for the creation of the `nbtc.bridge.near` account (or any new nBTC contract account).
2. Immediately after the WASM is deployed (but before the deployer's `new()` transaction lands), the attacker submits:
   ```json
   {
     "controller": "attacker.near",
     "bridge_id": "attacker.near",
     "name": "Near BTC",
     "symbol": "nBTC",
     "icon": null,
     "decimals": 8
   }
   ```
   to `nbtc.bridge.near::new`.
3. If the attacker's transaction is ordered before the deployer's, `env::state_exists()` is `false` and the call succeeds, setting `bridge_id = attacker.near`.
4. The deployer's subsequent `new()` call reverts with `"Already initialized"`.
5. The attacker calls `nbtc.bridge.near::mint` from `attacker.near` with `mint_account_id = attacker.near` and `mint_amount = 21_000_000_00000000` (21 million BTC in satoshis), minting unbacked nBTC.
6. The attacker transfers or sells the minted nBTC, draining real value from the bridge ecosystem. [1](#0-0) [4](#0-3)

### Citations

**File:** contracts/nbtc/src/lib.rs (L58-91)
```rust
    #[init]
    pub fn new(
        controller: AccountId,
        bridge_id: AccountId,
        name: String,
        symbol: String,
        icon: Option<String>,
        decimals: u8,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut contract = Self {
            controller,
            bridge_id,
            token: FungibleToken::new(StorageKey::FungibleToken),
            metadata: LazyOption::new(
                StorageKey::Metadata,
                Some(&FungibleTokenMetadata {
                    spec: FT_METADATA_SPEC.to_string(),
                    name,
                    symbol,
                    icon,
                    reference: None,
                    reference_hash: None,
                    decimals,
                }),
            ),
        };

        contract
            .token
            .internal_register_account(&contract.bridge_id);

        contract
    }
```

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L331-334)
```rust
impl Contract {
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/nbtc/src/lib.rs (L341-352)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: account_id,
            amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/nbtc/src/migrate.rs (L78-99)
```rust
    pub fn upgrade_and_migrate(&self) {
        self.assert_controller();

        // Receive the code directly from the input to avoid the
        // GAS overhead of deserializing parameters
        let code = env::input().unwrap_or_else(|| env::panic_str("ERR_NO_INPUT"));
        // Deploy the contract code.
        let promise_id = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise_id, &code);
        // Call promise to migrate the state.
        // Batched together to fail upgrade if migration fails.
        env::promise_batch_action_function_call(
            promise_id,
            "migrate",
            b"",
            NO_DEPOSIT,
            env::prepaid_gas()
                .saturating_sub(env::used_gas())
                .saturating_sub(OUTER_UPGRADE_GAS),
        );
        env::promise_return(promise_id);
    }
```

**File:** migrate/create_proposal.sh (L1-47)
```shellscript
EXPECTED_NBTC_BS58_HASH=4ELM6EPYWg9NXHGkYHPqeGFBrGCs4vQMZf7pMFQAnP4H
NBTC_ACCOUNT_ID=nbtc.bridge.near
DAO_ACCOUNT_ID=rainbowbridge.sputnik-dao.near
SIGNER_ACCOUNT_ID=bridge-ops.near
NEAR_NETWORK=mainnet

mkdir -p tmp

cd ../contracts/nbtc
cargo near build reproducible-wasm
cd ../../migrate

NBTC_WASM_PATH=../target/near/nbtc/nbtc.wasm
ACTUAL_NBTC_BS58_HASH=$(sha256sum $NBTC_WASM_PATH | awk '{print $1}' | xxd -r -p | base58)

if [[ "$ACTUAL_NBTC_BS58_HASH" != "$EXPECTED_NBTC_BS58_HASH" ]]; then
  echo "❌ Incorrect nBTC wasm hash"
  echo "Expected: $EXPECTED_NBTC_BS58_HASH"
  echo "Actual: $ACTUAL_NBTC_BS58_HASH"
  exit 1
fi

WASM_B64=$(base64 < $NBTC_WASM_PATH | tr -d '\n')

{
  echo '{
    "proposal": {
      "description": "Upgrade + migrate nBTC",
      "kind": {
        "FunctionCall": {
          "receiver_id": "'$NBTC_ACCOUNT_ID'",
          "actions": [
            {
              "method_name": "upgrade_and_migrate",
              "args": "'$WASM_B64'",
              "deposit": "0",
              "gas": "180000000000000"
            }
          ]
        }
      }
    }
  }'
} > ./tmp/proposal.json


near contract call-function as-transaction $DAO_ACCOUNT_ID add_proposal file-args ./tmp/proposal.json prepaid-gas '100.0 Tgas' attached-deposit '1 NEAR' sign-as $SIGNER_ACCOUNT_ID network-config $NEAR_NETWORK sign-with-keychain send
```
