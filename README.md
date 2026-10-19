# ELog: erasure-compatible, selectively disclosable, tamper-evident audit logs for AI agents

Reference prototype and experiments for the paper *Erasure-Compatible Tamper-Evident Audit Logs for Autonomous AI Agents with
Selective Disclosure and Blockchain Anchoring* (ICCSDI 2026 special track submission).

## Layout
| Path | Purpose |
|---|---|
| `elog.py` | ELog: salted per-field commitments, hash chain, Merkle epochs, Ed25519 signing, anchor ledger (simulated), disclosure, crypto-shredding, audit |
| `evalkit.py` | Attack matrix, forged-disclosure test, erasure evaluation, forensic demo (work on any ELog instance) |
| `experiments/synthetic_experiments.py` | Overhead, proof size, 100k-event audit, attack matrix, erasure, dictionary attack, crash injection, gas model |
| `agent/` | LLM tool-calling agent with simulated tools, indirect prompt-injection tasks, policy gate, log-before-act gateway |
| `notebooks/ELog_Agent_Colab.ipynb` | One-click run on a Colab A100 |
| `results/` | JSON results used in the paper |

## Run
Synthetic experiments (CPU, ~5 min): `pip install cryptography && python experiments/synthetic_experiments.py`

Agent experiment (GPU): open `notebooks/ELog_Agent_Colab.ipynb` in Colab (Runtime: A100), set `REPO_URL`, run all cells.
Offline pipeline test without a model: `python agent/run_agent.py --mock --out results/agent_mock.json` (mock output is NOT a result).

## Safety note
All tools (e-mail, funds transfer, SQL) are in-memory stubs. Injection texts target fake addresses (`evil-mail.test`) and fake accounts.

## Measuring real gas
Compile the two tiny contracts below in Remix (untested), deploy on the Remix VM, call `anchor()` several times and read the transaction cost.
Ignore the first `AnchorStore` call.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AnchorStore { bytes32[] public anchors; function anchor(bytes32 a) external { anchors.push(a); } }
contract AnchorEvent { event Anchored(uint256 indexed epoch, bytes32 root); function anchor(uint256 epoch, bytes32 root) external { emit Anchored(epoch, root); } }
```

## License
MIT. Research prototype, not production security software.
