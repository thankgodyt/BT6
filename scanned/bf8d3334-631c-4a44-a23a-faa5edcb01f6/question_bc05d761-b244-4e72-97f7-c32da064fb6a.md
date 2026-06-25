[File: 'evm/src/omni-bridge/contracts/OmniBridge.sol -> Scope: Critical. Balance manipulation, escrow mis-accounting, fee mis-accounting, decimal/normalization abuse, nonce/replay misuse, or token metadata binding confusion that changes user or protocol balances'] [Function: deployToken + finTransfer (decimal normalization)] Can an attacker submit a deployToken call with metadata.decimals > 18 (e.g., 24) to cause the deployed BridgeToken to have 18 decimals (via _normalizeDecimals) while NEAR records originDecimals=24 in the DeployToken event and uses it to scale amounts, under preconditions that (1) no token for metadata.token is yet deployed, (2) the attacker obtains or forges a valid NEAR MPC signature over the Met

```python
questions = [
