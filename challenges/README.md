# Challenges

The challenges use packaged synthetic fixtures or local lab services. Each directory contains its own brief and expected-findings contract or exercise instructions. The operator chooses where to run any live-service tool and is accountable for that use.

| Challenge | Practice | Input |
|---|---|---|
| [AWS 01 reachability](telecom-aws-01-reachability/README.md) | Public S3 reachability | `tf_s3_public_access` |
| [AWS 02 IAM and S3](telecom-aws-02-iam-s3-misconfig/README.md) | IAM/S3 configuration | `tf_iam_open` |
| [AWS 03 privilege path](telecom-aws-03-iam-privesc/README.md) | Assume-role paths | `tf_iam_assume_role`, `tf_iam_external_trust` |
| [AWS 04 network exposure](telecom-aws-04-network-exposure/README.md) | Network exposure and near misses | `tf_sg_open_ingress`, `tf_s3_policy_blocked_trap` |
| [AWS 05 logging](telecom-aws-05-logging-gaps/README.md) | Detection and logging gaps | `tf_cloudtrail_disabled`, `tf_s3_no_access_logging` |
| [AWS 06 chain](telecom-aws-06-chain-rehearsal/README.md) | Multi-stage finding set | `tf_chain_ingress_role` and related fixtures |
| [Web DAST](lab-web-01-dast-surface/README.md) | Web service observation | Local lab target |
| [Network discovery](lab-net-01-service-discovery/README.md) | Service discovery | Local lab target |
| [Attack mapping](lab-knowledge-01-attack-mapping/README.md) | ATT&CK mapping | Synthetic fixtures |
| [Edge posture](lab-edge-01-device-posture/README.md) | Device service posture | Local lab target |
| [Caldera listings](lab-emu-01-caldera-listings/README.md) | Emulation catalog | Configured Caldera endpoint |
| [Metasploit listings](lab-emu-02-msf-listings/README.md) | Module catalog | Configured Metasploit endpoint |
| [Semgrep review](lab-code-01-semgrep-review/README.md) | Static code review | Planted source |

Additional self-study exercises cover [tool-event interpretation](lab-agent-01-tool-boundary/README.md), [technique-to-detection reasoning](lab-detect-01-technique-chain/README.md), [threat-model review](lab-review-01-threat-model/README.md), and [Kubernetes RBAC paths](lab-k8s-01-rbac-path/instructor/KEY.md).

For a challenge with `artifacts/expected-findings.json`, grade a submission from that challenge directory with:

```sh
python -m score --grade my-findings.json --expected artifacts/expected-findings.json
```

A passing grade means the findings match the planted contract. Review the explanation and tool output as well. See the [instructor guide](../INSTRUCTOR_GUIDE.md) and [operations](../OPERATIONS.md) for setup and cleanup.
