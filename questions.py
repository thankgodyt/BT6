import json
import os


# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "IntersectMBO/ouroboros-consensus"
# todo: the name of the repository
REPO_NAME = "ouroboros-consensus"
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
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/TPraos.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Header.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/VRF.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Views.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Common.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/AgentClient.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Ledger/HotKey.hs",
    "ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Ledger/Util.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderValidation.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HeaderStateHistory.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Forecast.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/Abstract.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/Forging.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsProtocol.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/Abstract.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/BFT.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/Crypto.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/State.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/Signed.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/LeaderSchedule.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/ModChainSel.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Genesis/Governor.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Abstract.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Basics.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Extended.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsMempool.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsProtocol.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsPeras.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Basics.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Diff.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/API.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Impl/Common.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Init.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/TxSeq.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Update.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Block.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Mempool.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Node.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/ChainSel.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/LedgerView.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Serialisation/SerialiseDisk.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Serialisation/SerialiseNodeToClient.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Serialisation/SerialiseNodeToNode.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State/Infra.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State/Types.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Translation.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EpochInfo.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Summary.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Background.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/BlockCache.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Follower.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Iterator.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Types.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/API.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Parser.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/State.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Validation.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/API.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/Forker.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/Snapshots.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2/Backend.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2/Forker.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2/InMemory.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2/LedgerSeq.hs",
    "ouroboros-consensus/src/ouroboros-consensus-lsm/Ouroboros/Consensus/Storage/LedgerDB/V2/LSM.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/API.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl/Index.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl/Parser.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl/State.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/Server.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/HistoricityCheck.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/InFutureCheck.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/Jumping.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Server.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalStateQuery/Server.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalTxSubmission/Server.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Outbound.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs",
    "ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToClient.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/GSM.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Recovery.hs",
    "ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/NodeKernel.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Block.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/CanHardFork.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Ledger.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs",
    "ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/QueryHF.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Protocol.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/HeaderValidation.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/Mempool.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/PBFT.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Node.hs",
    "ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Node/Serialisation.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Block.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Config.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Forge.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Mempool.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Protocol.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/SupportsProtocol.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Common.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Praos.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/TPraos.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Serialisation.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Praos.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/TPraos.hs",
    "ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs",
]

target_scopes = [
    "Critical. Consensus safety failure that lets an unprivileged peer or crafted on-disk/network input make a node accept an invalid block, invalid header, invalid ledger state, double-spend, or irreversible divergent chain",
    "Critical. Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks, or hot-key rules that enables unauthorized block, vote, or certificate acceptance",
    "High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions",
    "High. Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes",
    "High. ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshot, or LSM corruption/replay/rollback bug that causes durable use of the wrong ledger state or permanent acceptance/rejection of a valid chain without operator fault",
    "Medium. Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS",
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one Ouroboros Consensus target.

    target_file format:
    "'File Name: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs -> Scope: High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact Ouroboros Consensus target:

    {target_file}

    Use live context from this repository if available: Praos, TPraos, PBFT, BFT, Peras votes/certificates, committee logic, header validation, VRF/KES/hot-key checks, chain selection, Genesis governor, ChainSync, BlockFetch, LocalTxSubmission, object diffusion, HardFork Combinator, ledger views, forecasts, era transitions, mempool, ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshots, LSM backend, Cardano/Byron/Shelley integration, serialization, and network-version negotiation.

    Protocol focus:
    Ouroboros Consensus implements Cardano node consensus, storage, diffusion, and protocol integration. The audit target is production repository code covered by the Intersect POSM Bug Bounty and SECURITY.md. Exclude tests, docs, mocks, generators, benches, local tools, automation, unstable test libraries, and deployment-only configuration.

    Core invariants:

    * Invalid blocks, headers, ledger states, votes, certificates, or transactions must never be accepted as valid.
    * Honest nodes must not be driven by unprivileged peers into a divergent, non-canonical, or rollback-invalid chain outside protocol security assumptions.
    * VRF, KES, hot-key, PBFT/Praos/TPraos, Peras, committee, and ledger-view checks must preserve authorization and threshold assumptions.
    * Hard-fork era boundaries, forecasts, network versions, serialization formats, and ledger translations must not let data from one era/protocol be accepted under another.
    * ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshots, and LSM state must remain consistent across validation, rollback, replay, restart, and recovery.

    Rules:

    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Attacker may be an unprivileged peer, block/header sender, ChainSync/BlockFetch/NodeToNode participant, LocalTxSubmission or LocalStateQuery client, object-diffusion sender, crafted DB/snapshot input provider in a local reproduction, or creator of protocol messages accepted by the node.
    * Do not rely on admin/operator compromise, leaked keys, malicious maintainers, social engineering, physical attacks, compromised Cardano ledger rules, external dependency bugs alone, stake majority, VRF/KES key compromise, trusted genesis/config changes, public-mainnet testing, spam, or brute-force DoS.
    * Exclude denial of service, network outages, resource exhaustion, performance-only bugs, logging/metrics issues, code style, best-practice findings, test-only paths, docs, configs, generated files, scripts, local tooling, benchmarks, mocks, and unstable test libraries.
    * Generate 10 to 20 high-signal questions.
    * At least 70% must be multi-step flow, invariant, authorization, consensus-safety, chain-selection, hard-fork, storage-replay, serialization, rollback, or cross-module questions.
    * Every question must be testable by a runnable unit test, state-machine test, property/fuzz test, io-sim scenario, model/differential test, local node cluster, or private-testnet sequence.
    * Avoid generic checklist questions and repeated root causes; prefer boundary mutations such as wrong era, stale ledger view, forged header field, duplicate vote, rollback/replay edge, restart boundary, corrupted snapshot, mismatched network version, invalid certificate, or malformed serialized block.
    * Each question must target a plausible issue class for the exact file and scope.

    High-value attack surfaces:

    * Protocol validation: header body hashes, slot checks, VRF leader eligibility, KES periods, operational certificates, overlay schedules, PBFT delegation state, Praos/TPraos chain order, Peras votes/certs, committee weights, and ledger views.
    * Chain selection and diffusion: candidate selection, headers before blocks, ChainSync rollback, BlockFetch validation, Genesis density checks, historicity/future checks, peer-triggered state transitions, and object-diffusion acceptance.
    * Hard forks: era boundary translation, forecast windows, network-version gates, node-to-node/node-to-client serialization, query dispatch, and cross-era ledger/protocol state.
    * Storage and restart: ChainDB validation, VolatileDB indexes, ImmutableDB chunk/index parsing, LedgerDB snapshots, rollback/replay after restart, LSM/in-memory backend consistency, and database recovery.
    * Mempool and local APIs: transaction validation against ledger state, mempool revalidation, local submission/query authorization boundaries, and transaction sequence invariants.

    Impact mapping:

    * Valid impacts are only the provided Critical, High, or Medium scoped impact. Do not downgrade or expand the scope.

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
    Generate a focused Ouroboros Consensus exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production Ouroboros Consensus code listed in `scope_files`.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, docs, mocks, generators, benchmarks, generated files, repo automation scripts, configs, build files, IDE files, examples, local tools, and unstable test libraries.
- Respect SECURITY.md and the Intersect POSM Bug Bounty rules. Do not perform public-mainnet testing; prefer local tests, io-sim, model tests, or private testnets.

## Objective
Decide whether the question leads to a real, reachable Ouroboros Consensus vulnerability.
The attacker must enter through a supported production path: NodeToNode/NodeToClient protocol message, ChainSync, BlockFetch, LocalTxSubmission, LocalStateQuery, object diffusion, block/header validation, mempool validation, database replay/recovery, snapshot loading, hard-fork transition, or a supported local/private-testnet reproduction of those paths.
The impact must match the provided target scope.
Prefer #NoVulnerability unless the path is concrete, locally testable on unmodified code, and proves one impact in `target_scopes`.

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production files/functions across protocol, diffusion, hard-fork, ledger, mempool, storage, Peras/committee, or Cardano integration modules.
3. Check relevant guards: header validation, ledger validation, VRF/KES/hot-key checks, certificate/vote verification, chain selection, rollback limits, forecast windows, era/network-version checks, serialization tags, DB indexes, snapshot integrity, and replay/recovery logic.
4. Decide whether the questioned invariant can actually break under intended deployment.
5. Prove root cause with file/function/line references.
6. Confirm realistic likelihood and exact scoped impact.
7. Reject if current validation already prevents the exploit.

## Reject Immediately
- Requires admin/operator compromise, leaked keys, malicious maintainer, social engineering, physical attack, trusted config/genesis manipulation, stake majority, VRF/KES key compromise, external dependency bug alone, public-mainnet testing, spam, or brute-force DoS.
- Only affects tests, docs, configs, scripts, mocks, generators, benches, generated code, local tooling, deployment choices, or unstable test libraries.
- Impact is denial of service, network outage, resource exhaustion, performance degradation, logging/observability, harmless rejection, stale read with no security impact, or non-security correctness.
- No concrete scoped impact or no realistic exploit path.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Consensus safety failure that lets an unprivileged peer or crafted on-disk/network input make a node accept an invalid block, invalid header, invalid ledger state, double-spend, or irreversible divergent chain.
- Critical. Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks, or hot-key rules that enables unauthorized block, vote, or certificate acceptance.
- High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.
- High. Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes.
- High. ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshot, or LSM corruption/replay/rollback bug that causes durable use of the wrong ledger state or permanent acceptance/rejection of a valid chain without operator fault.
- Medium. Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS.

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
    Generate a short cross-project analog scan prompt for Ouroboros Consensus.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production Ouroboros Consensus files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, docs, build files, IDE files, configs, generated files, resources, repo automation scripts, local tooling, benchmarks, mocks, or unstable test libraries as audited targets.

## Objective
Use the external report's vulnerability class as a hint to find valid issues based on Ouroboros Consensus security impact.
Focus on externally reachable issues triggered by an unprivileged peer/client, crafted block/header/transaction/object, protocol message, DB/snapshot input in a local reproduction, or private-testnet sequence.
Only report an analog if this repository has its own reachable root cause and the impact matches the provided target scope.

## Method
1. Classify vuln type: invalid block/header acceptance, validation bypass, chain-selection error, rollback/replay bug, hard-fork era confusion, serialization mismatch, ledger-view/forecast bug, DB/snapshot corruption, certificate/vote verification bypass, or sensitive consensus-state exposure.
2. Map to Ouroboros Consensus components and exact production files.
3. Prove root cause with exact file/function/module/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Explain the attacker-controlled entry path and why this code is a necessary vulnerable step.
6. Reject if the impact does not match the provided target scope.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires admin/operator compromise, leaked keys, malicious maintainer, social engineering, physical attack, trusted config/genesis manipulation, stake majority, VRF/KES key compromise, external dependency bug alone, public-mainnet testing, spam, or brute-force DoS.
- Test/docs/config/build/generated/local-tooling/benchmark/mock/unstable-testlib issue.
- Theoretical-only issue with no consensus/security impact.
- Impact is denial of service, network outage, resource exhaustion, performance degradation, logging/observability, harmless rejection, stale read with no security impact, or non-security correctness.
- Impact or likelihood missing.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Consensus safety failure that lets an unprivileged peer or crafted on-disk/network input make a node accept an invalid block, invalid header, invalid ledger state, double-spend, or irreversible divergent chain.
- Critical. Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks, or hot-key rules that enables unauthorized block, vote, or certificate acceptance.
- High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.
- High. Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes.
- High. ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshot, or LSM corruption/replay/rollback bug that causes durable use of the wrong ledger state or permanent acceptance/rejection of a valid chain without operator fault.
- Medium. Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS.

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
    Generate a strict Ouroboros Consensus validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and the Intersect POSM Bug Bounty rules for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, operator-only, trusted-maintainer, leaked-key, best-practice, docs/style, denial-of-service, resource-exhaustion, performance-only, griefing-only, static-analysis-only, dependency-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, missing external context, unsupported protocol behavior, trusted config/genesis manipulation, stake majority, VRF/KES key compromise, social engineering, public-mainnet testing, or physical attacks.
- A valid report must be triggerable by an unprivileged peer/client or crafted production input through NodeToNode/NodeToClient protocols, ChainSync, BlockFetch, LocalTxSubmission, LocalStateQuery, object diffusion, block/header validation, mempool validation, DB replay/recovery, snapshot loading, or hard-fork transitions.
- The final impact must match one of `target_scopes`, not just a generic code bug.
- Prefer #NoVulnerability over speculative reports.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Consensus safety failure that lets an unprivileged peer or crafted on-disk/network input make a node accept an invalid block, invalid header, invalid ledger state, double-spend, or irreversible divergent chain.
- Critical. Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks, or hot-key rules that enables unauthorized block, vote, or certificate acceptance.
- High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.
- High. Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes.
- High. ChainDB, ImmutableDB, VolatileDB, LedgerDB, snapshot, or LSM corruption/replay/rollback bug that causes durable use of the wrong ledger state or permanent acceptance/rejection of a valid chain without operator fault.
- Medium. Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS.

If the submitted claim does not concretely prove one of the allowed impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken consensus, authorization, storage, hard-fork, or ledger/security invariant.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete impact that exactly matches one allowed Ouroboros Consensus impact above, with realistic likelihood.
6. Reproducible proof path: unit/integration/property/fuzz/state-machine/io-sim/model/differential test, local node cluster, or private-testnet sequence.
7. No obvious rejection reason from SECURITY.md, Intersect POSM rules, known audit findings, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal peer/client, crafted block/header/transaction/object sender, or crafted DB/snapshot input in a local reproduction trigger this?
- Does the code actually behave as claimed?
- Is the impact caused by this repository, not by an external dependency alone?
- Is the consensus/authorization/storage/hard-fork impact concrete, not hypothetical?
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
[Concrete allowed Ouroboros Consensus impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/model/io-sim/private-testnet test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
