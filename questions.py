import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "Near-One/omni-bridge"
# todo: the name of the repository
REPO_NAME = "omni-bridge"
run_number = os.environ.get('GITHUB_RUN_NUMBER') or os.environ.get('CI_PIPELINE_IID', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"

scope_files = [
    'evm/src/common/Borsh.sol',
    'evm/src/common/IBridgeToken.sol',
    'evm/src/common/ICustomMinter.sol',
    'evm/src/eNear/contracts/ENearProxy.sol',
    'evm/src/eNear/contracts/IENear.sol',
    'evm/src/omni-bridge/contracts/BridgeToken.sol',
    'evm/src/omni-bridge/contracts/BridgeTypes.sol',
    'evm/src/omni-bridge/contracts/HlBridgeToken.sol',
    'evm/src/omni-bridge/contracts/OmniBridge.sol',
    'evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol',
    'evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol',
    'near/omni-bridge/src/btc.rs',
    'near/omni-bridge/src/lib.rs',
    'near/omni-bridge/src/migrate.rs',
    'near/omni-bridge/src/storage.rs',
    'near/omni-bridge/src/token_lock.rs',
    'near/omni-prover/evm-prover/src/lib.rs',
    'near/omni-prover/mpc-omni-prover/src/lib.rs',
    'near/omni-prover/wormhole-omni-prover-proxy/src/byte_utils.rs',
    'near/omni-prover/wormhole-omni-prover-proxy/src/lib.rs',
    'near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs',
    'near/omni-token/src/lib.rs',
    'near/omni-token/src/migrate.rs',
    'near/omni-token/src/omni_ft.rs',
    'near/omni-types/src/bounded_string.rs',
    'near/omni-types/src/btc.rs',
    'near/omni-types/src/errors.rs',
    'near/omni-types/src/evm/events.rs',
    'near/omni-types/src/evm/header.rs',
    'near/omni-types/src/evm/mod.rs',
    'near/omni-types/src/evm/receipt.rs',
    'near/omni-types/src/hex_types.rs',
    'near/omni-types/src/lib.rs',
    'near/omni-types/src/locker_args.rs',
    'near/omni-types/src/mpc_types.rs',
    'near/omni-types/src/near_events.rs',
    'near/omni-types/src/prover_args.rs',
    'near/omni-types/src/prover_result.rs',
    'near/omni-types/src/sol_address.rs',
    'near/omni-types/src/starknet/events.rs',
    'near/omni-types/src/starknet/mod.rs',
    'near/omni-types/src/utils.rs',
    'near/token-deployer/src/lib.rs',
    'near/token-deployer/src/migrate.rs',
    'solana/programs/bridge_token_factory/src/constants.rs',
    'solana/programs/bridge_token_factory/src/error.rs',
    'solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs',
    'solana/programs/bridge_token_factory/src/instructions/admin/initialize.rs',
    'solana/programs/bridge_token_factory/src/instructions/admin/mod.rs',
    'solana/programs/bridge_token_factory/src/instructions/admin/pause.rs',
    'solana/programs/bridge_token_factory/src/instructions/admin/update_metadata.rs',
    'solana/programs/bridge_token_factory/src/instructions/mod.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer_sol.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/get_version.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs',
    'solana/programs/bridge_token_factory/src/instructions/user/mod.rs',
    'solana/programs/bridge_token_factory/src/instructions/wormhole_cpi.rs',
    'solana/programs/bridge_token_factory/src/lib.rs',
    'solana/programs/bridge_token_factory/src/state/config.rs',
    'solana/programs/bridge_token_factory/src/state/message/deploy_token.rs',
    'solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs',
    'solana/programs/bridge_token_factory/src/state/message/init_transfer.rs',
    'solana/programs/bridge_token_factory/src/state/message/log_metadata.rs',
    'solana/programs/bridge_token_factory/src/state/message/mod.rs',
    'solana/programs/bridge_token_factory/src/state/mod.rs',
    'solana/programs/bridge_token_factory/src/state/used_nonces.rs',
    'starknet/src/bridge_token.cairo',
    'starknet/src/bridge_types.cairo',
    'starknet/src/lib.cairo',
    'starknet/src/omni_bridge.cairo',
    'starknet/src/utils.cairo',
    'starknet/src/utils/borsh.cairo',
]

target_scopes = [
    'Critical. Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows',
    'Critical. Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions',
    'Critical. Balance manipulation, escrow mis-accounting, fee mis-accounting, decimal/normalization abuse, nonce/replay misuse, or token metadata binding confusion that changes user or protocol balances',
    'Critical. Cross-chain replay, message forgery, event/proof parsing flaw, light-client verification bypass, Wormhole VAA verification bypass, or chain/domain separation flaw enabling invalid finalization or double-spending',
    'Critical. Cryptographic or MPC-related flaw causing unauthorized access to signing capability, acceptance of invalid signatures/proofs, bypass of threshold-signature requirements, or sensitive MPC state disclosure',
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one NEAR Omni Bridge target.

    target_file format:
    "'File Name: near/omni-bridge/src/lib.rs -> Scope: Critical. Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact NEAR Omni Bridge target:

    {target_file}

    Use live context from the project if available: NEAR omni-bridge, NEAR omni-token, token-deployer, omni-types, EVM prover, MPC omni prover, Wormhole omni prover proxy, EVM OmniBridge contracts, ENear proxy, Solana bridge token factory, Starknet omni bridge, Borsh/message encoders, cross-chain event parsing, proof verification, token deployment, token binding, init/finalize transfer flows, fees, nonces, relayer/staking gates, pause/admin roles, storage accounting, and migration paths.

    Protocol focus:
    NEAR Omni Bridge is a multi-chain asset bridge. NEAR-to-foreign-chain outbound transfers use Chain Signatures/MPC signing. Foreign-chain-to-NEAR inbound transfers use light clients for Ethereum, Bitcoin, and Zcash, and Wormhole for Solana, BNB, EVM L2s, and other Wormhole-routed chains. The audit target is production smart contract and verifier/prover code in this repository only.

    Core invariants:

    * User or protocol funds must never be stolen, lost, double-spent, permanently frozen, minted without backing, released without locking/burning, or finalized more than once.
    * Only authorized users, relayers, managers, token contracts, provers, bridge contracts, and configured admins may execute privileged bridge, token, deployer, pause, upgrade, fee, or configuration actions.
    * Escrow balances, bridged token supply, native token accounting, fee accounting, decimal normalization, storage deposits, callbacks/refunds, metadata bindings, and recipient amounts must remain consistent across all supported chains.
    * Cross-chain messages, VAAs, light-client proofs, receipts, events, headers, signatures, emitters, chain IDs, token IDs, recipient formats, nonces, and domains must not be forgeable, replayable, malleable, duplicated, or accepted for the wrong chain or asset.
    * MPC, threshold-signature, signer, prover, and verification logic must never expose sensitive state or accept signatures/proofs that do not meet the required authorization and threshold assumptions.

    Rules:

    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Attacker may be an unprivileged bridge user, token holder, malicious recipient, relayer applicant, custom relayer, caller of public smart-contract methods, contract deployer through supported factory paths, or creator of cross-chain messages/events/proofs accepted by the bridge.
    * Do not rely on admin/operator compromise; leaked private keys; malicious maintainer; social engineering; physical or TEE hardware attacks; Wormhole guardian compromise; NEAR validator collusion, chain reorgs, or finality failures; control of >= threshold colluding MPC nodes; unsupported local configuration; public-mainnet testing; front-running-only attacks; spam; or brute-force DDoS.
    * Exclude denial of service, network-level outages, unbounded gas/storage consumption, griefing with no profit motive, dependency-only issues, static-analysis-only findings, gas optimizations, code style, best-practice findings, already-known audit findings, in-memory secret zeroization, RNG quality, mock attestation acceptance during the grace period, deployment/operational issues, and planned designs without code.
    * Exclude test-only code paths, mocks, examples, docs, configs, generated files, local scripts, repo automation, and non-default feature-only paths such as dev-utils, test-utils, benchmark, or network-hardship-simulation features.
    * Generate 10 to 20 high-signal questions.
    * At least 70% must be multi-step flow, invariant, authorization, accounting, proof-verification, cross-chain replay, message-domain, token-binding, nonce, finalization, migration, or cross-module questions.
    * Every question must be testable by a runnable localnet/testnet-safe PoC, contract unit test, fuzz test, invariant test, model test, differential test, or private-testnet transaction sequence.
    * Avoid generic checklist questions and repeated root causes; prefer boundary mutations such as wrong emitter, wrong chain ID, duplicate event, failed callback, reordered finalization, malformed recipient, reused nonce, mismatched decimals, or partial state update.
    * Each question must target a plausible issue class for the exact file and scope.

    High-value attack surfaces:

    * NEAR bridge flows: `ft_transfer_call`, `storage_deposit`, `init_transfer`, `fin_transfer`, `bind_token`, `deploy_token`, BTC/Zcash handling, fee/native-fee handling, relayer staking, trusted relayer gates, pause/admin gates, migrations, refunds, and storage-accounting state.
    * NEAR token/deployer flows: bridged token mint/burn/transfer behavior, metadata binding, deployer authorization, account registration, promise callback failure, refund paths, and migration compatibility.
    * Prover and verifier flows: EVM receipt/header/event parsing, Wormhole VAA parsing and proxying, Bitcoin/Zcash proof data, Borsh encoders, emitter/chain/domain separation, finality assumptions, result decoding, and proof freshness.
    * EVM bridge flows: `initTransfer`, `finTransfer`, `deployToken`, `logMetadata`, custom minter behavior, ERC20/1155 handling, ENear proxy behavior, selective pausing, bridge token implementation, fee accounting, signatures, and nonce replay protection.
    * Solana and Starknet flows: bridge token factory initialization/configuration, PDA/account ownership checks, Wormhole CPI, SPL/SOL init/finalize transfer, used nonce state, message serialization, Cairo bridge/token state updates, and recipient/token identifier validation.
    * Cross-chain consistency: source/destination chain identifiers, token IDs, metadata hashes, decimals, amount normalization, recipient formats, event topics/selectors, message hashes, replay domains, and one-time finalization state.

    Impact mapping:

    * Critical only: theft/loss/freezing/double-spending of funds; unauthorized transaction or privileged action; bridge balance, escrow, fee, or token-supply manipulation; cross-chain replay or verification bypass enabling invalid finalization; cryptographic/MPC/signature bypass or sensitive MPC state disclosure.

    Each question must include:

    1. target function/module;
    2. attacker action;
    3. preconditions;
    4. call sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_module] Can an attacker ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: fuzz/state-test PARAMETERS and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused NEAR Omni Bridge exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production NEAR Omni Bridge smart-contract, verifier, prover, and message/type code listed in `scope_files`.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, docs, mocks, generated files, repo automation scripts, configs, build files, IDE files, package metadata, local deployment choices, examples, and local tooling.
- Respect SECURITY.md and the HackenProof program rules. Do not perform public-mainnet testing; prefer local tests or private testnets.

## Objective
Decide whether the question leads to a real, reachable NEAR Omni Bridge vulnerability.
The attacker must enter through a supported production path: public smart-contract call, token transfer callback, cross-chain transfer initiation/finalization, metadata logging, token deployment/binding, relayer flow, prover/verifier input, accepted cross-chain message/event/proof, or a supported local/private-testnet reproduction of those paths.
The impact must match the provided target scope.
Prefer #NoVulnerability unless the path is concrete, locally testable on unmodified code, and proves one of the Critical impacts in `target_scopes`.

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production files/functions across NEAR, EVM, Solana, Starknet, or prover/type modules.
3. Check relevant guards: predecessor/signer checks, role checks, pause gates, token/account ownership, storage deposits, callbacks/refunds, nonce/used-message state, amount/fee/decimal accounting, metadata binding, token ID parsing, signature/proof verification, emitter/chain/domain separation, finality checks, and replay/idempotence protection.
4. Decide whether the questioned invariant can actually break under intended deployment.
5. Prove root cause with file/function/line references.
6. Confirm realistic likelihood and exact scoped impact.
7. Reject if current validation already prevents the exploit.

## Reject Immediately
- Requires admin/operator compromise, leaked private keys, malicious maintainer, social engineering, physical or TEE hardware attacks, Wormhole guardian compromise, NEAR validator collusion/reorg/finality failure, >= threshold colluding MPC nodes, unsupported local configuration, public-mainnet testing, front-running only, spam, or brute-force DDoS.
- Only affects tests, docs, configs, scripts, mocks, generated code, local tooling, deployment choices, or non-default feature-only paths.
- External dependency behavior is the only cause.
- Impact is denial of service, unbounded gas/storage consumption, network outage, performance degradation, griefing without profit motive, logging/observability, local misconfiguration, harmless rejection, stale read with no fund/security impact, in-memory secret zeroization, RNG quality, or theoretical risk.
- No concrete scoped impact or no realistic exploit path.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows.
- Critical. Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions.
- Critical. Balance manipulation, escrow mis-accounting, fee mis-accounting, decimal/normalization abuse, nonce/replay misuse, or token metadata binding confusion that changes user or protocol balances.
- Critical. Cross-chain replay, message forgery, event/proof parsing flaw, light-client verification bypass, Wormhole VAA verification bypass, or chain/domain separation flaw enabling invalid finalization or double-spending.
- Critical. Cryptographic or MPC-related flaw causing unauthorized access to signing capability, acceptance of invalid signatures/proofs, bypass of threshold-signature requirements, or sensitive MPC state disclosure.

## Output
If valid:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If invalid, output exactly:
#NoVulnerability found for this question.
"""


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for NEAR Omni Bridge.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production NEAR Omni Bridge files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, docs, build files, IDE files, configs, generated files, resources, package metadata, repo automation scripts, local tooling, deployment-only choices, or non-default feature-only paths as audited targets.

## Objective
Use the external report's vulnerability class as a hint to find valid issues based on NEAR Omni Bridge security impact.
Focus on externally reachable issues triggered by an unprivileged bridge user, token holder, malicious recipient, relayer applicant, custom relayer, public smart-contract caller, contract deployer through supported factory paths, or creator of cross-chain messages/events/proofs accepted by the bridge.
Only report an analog if this repository has its own reachable root cause and the impact matches the provided target scope.

## Method
1. Classify vuln type: unauthorized transaction, role/auth bypass, pause bypass, balance manipulation, escrow/token-supply mis-accounting, callback/refund inconsistency, fee/decimal normalization abuse, token metadata binding confusion, nonce/replay bug, cross-chain message forgery, event/proof parsing flaw, light-client/Wormhole verification bypass, signature/MPC threshold bypass, or sensitive MPC state disclosure.
2. Map to NEAR Omni Bridge components and exact production files.
3. Prove root cause with exact file/function/module/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Explain the attacker-controlled entry path and why this code is a necessary vulnerable step.
6. Reject if the impact does not match the provided target scope.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires admin/operator compromise, leaked private keys, malicious maintainer, social engineering, physical or TEE hardware attacks, Wormhole guardian compromise, NEAR validator collusion/reorg/finality failure, >= threshold colluding MPC nodes, unsupported local configuration, public-mainnet testing, front-running only, spam, or brute-force DDoS.
- External dependency behavior is the only cause.
- Test/docs/config/build/generated/local-tooling/deployment-only/non-default-feature issue.
- Theoretical-only issue with no protocol impact.
- Impact is denial of service, unbounded gas/storage consumption, network outage, performance degradation, griefing without profit motive, local misconfiguration, observability noise, logging noise, harmless rejection, stale read with no security impact, or non-security correctness.
- Impact or likelihood missing.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows.
- Critical. Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions.
- Critical. Balance manipulation, escrow mis-accounting, fee mis-accounting, decimal/normalization abuse, nonce/replay misuse, or token metadata binding confusion that changes user or protocol balances.
- Critical. Cross-chain replay, message forgery, event/proof parsing flaw, light-client verification bypass, Wormhole VAA verification bypass, or chain/domain separation flaw enabling invalid finalization or double-spending.
- Critical. Cryptographic or MPC-related flaw causing unauthorized access to signing capability, acceptance of invalid signatures/proofs, bypass of threshold-signature requirements, or sensitive MPC state disclosure.


## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict NEAR Omni Bridge validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and the HackenProof Near Intents Bridges program rules for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, operator-only, trusted-maintainer, leaked-key, best-practice, docs/style, gas-only, denial-of-service, unbounded gas/storage, performance-only, griefing-only, front-running-only, static-analysis-only, dependency-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, missing external context, unsupported protocol behavior, Wormhole guardian compromise, NEAR validator collusion/reorg/finality failure, >= threshold colluding MPC nodes, unsupported local configuration, social engineering, public-mainnet testing, or physical/TEE hardware attacks.
- A valid report must be triggerable by an unprivileged external user through public smart-contract calls, token callbacks, cross-chain transfer/init/finalize flows, metadata logging, token deployment/binding, relayer flows, prover/verifier input, or accepted cross-chain messages/events/proofs.
- The final impact must match one of the Critical `target_scopes`, not just a generic code bug.
- Prefer #NoVulnerability over speculative reports.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows.
- Critical. Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions.
- Critical. Balance manipulation, escrow mis-accounting, fee mis-accounting, decimal/normalization abuse, nonce/replay misuse, or token metadata binding confusion that changes user or protocol balances.
- Critical. Cross-chain replay, message forgery, event/proof parsing flaw, light-client verification bypass, Wormhole VAA verification bypass, or chain/domain separation flaw enabling invalid finalization or double-spending.
- Critical. Cryptographic or MPC-related flaw causing unauthorized access to signing capability, acceptance of invalid signatures/proofs, bypass of threshold-signature requirements, or sensitive MPC state disclosure.

If the submitted claim does not concretely prove one of the allowed impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken bridge/security/accounting assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete impact that exactly matches one allowed NEAR Omni Bridge impact above, with realistic likelihood.
6. Reproducible proof path: local unit/integration/fuzz/invariant test, private-testnet transaction sequence, contract call sequence, or justified model/differential test when localnet cannot demonstrate the impact.
7. No obvious rejection reason from SECURITY.md, HackenProof rules, known audit findings, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external user, token holder, custom relayer, relayer applicant, or cross-chain message/proof creator trigger this?
- Does the code actually behave as claimed?
- Is the impact caused by this repository, not by an external dependency alone?
- Is the fund/authorization/accounting/proof/MPC impact concrete, not hypothetical?
- Would a responsible-disclosure triager accept the proof?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the bug and impact]

## Finding Description
[Exact code path, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[Concrete allowed NEAR Omni Bridge impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/model/private-testnet test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt

