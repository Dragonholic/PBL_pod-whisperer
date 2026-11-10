# v2 research sources (2026-11-05)

Full write-up with explanations: Notion "2차 실험 — 계획 (논문·공식 문서 기반 조건 조사)".
Every DOI below was checked against Crossref (title + authors + year matched).
Two DOIs first written from memory were wrong and were replaced (Jung 2004, Staniford 2002).

Verification level: A = page/abstract opened and read, B = bibliographic data
verified but full text NOT read (confirm before quoting), C = search results only.

## Papers / standards (with DOI)

| ID | Reference | DOI | Level |
|---|---|---|---|
| P1 | Staniford, Hoagland, McAlerney. Practical automated detection of stealthy portscans. J. Computer Security 10(1-2):105-136, 2002 | https://doi.org/10.3233/jcs-2002-101-205 | B |
| P2 | Jung, Paxson, Berger, Balakrishnan. Fast portscan detection using sequential hypothesis testing. IEEE S&P 2004, pp.211-225 | https://doi.org/10.1109/SECPRI.2004.1301325 | B |
| P3 | Axelsson. The base-rate fallacy and the difficulty of intrusion detection. ACM TISSEC 3(3):186-205, 2000 | https://doi.org/10.1145/357830.357849 | B |
| P4 | Sommer, Paxson. Outside the closed world: On using machine learning for network intrusion detection. IEEE S&P 2010, pp.305-316 | https://doi.org/10.1109/SP.2010.25 | B |
| P5 | Chandola, Banerjee, Kumar. Anomaly detection: A survey. ACM Computing Surveys 41(3):1-58, 2009 | https://doi.org/10.1145/1541880.1541882 | B |
| P6 | Valeur, Vigna, Kruegel, Kemmerer. A comprehensive approach to intrusion detection alert correlation. IEEE TDSC 1(3):146-169, 2004 | https://doi.org/10.1109/TDSC.2004.21 | B |
| P7 | Bufalino, Martin-Navarro, Di Francesco, Aura. Inside Job: Defending Kubernetes Clusters Against Network Misconfigurations. Proc. ACM on Networking 3, 2025 (arXiv:2506.21134) | https://doi.org/10.1145/3749220 | A (abstract) |
| P8 | Souppaya, Morello, Scarfone. Application Container Security Guide. NIST SP 800-190, 2017 | https://doi.org/10.6028/NIST.SP.800-190 | A (abstract) |
| P9 | Sultan, Ahmad, Dimitriou. Container Security: Issues, Challenges, and the Road Ahead. IEEE Access 7:52976-52996, 2019 | https://doi.org/10.1109/ACCESS.2019.2911732 | B |
| P10 | Scarfone, Mell. Guide to Intrusion Detection and Prevention Systems (IDPS). NIST SP 800-94, 2007 | https://doi.org/10.6028/NIST.SP.800-94 | B |

## Official documents (no DOI)

| ID | Document | URL | Level |
|---|---|---|---|
| D1 | MITRE ATT&CK T1046 Network Service Discovery | https://attack.mitre.org/techniques/T1046/ | A |
| D2 | MITRE ATT&CK T1613 Container and Resource Discovery | https://attack.mitre.org/techniques/T1613/ | A |
| D3 | MITRE ATT&CK TA0008 Lateral Movement | https://attack.mitre.org/tactics/TA0008/ | A |
| D4 | Kubernetes docs: Ports and Protocols | https://kubernetes.io/docs/reference/networking/ports-and-protocols/ | A |
| D5 | Kubernetes docs: Network Policies | https://kubernetes.io/docs/concepts/services-networking/network-policies/ | A (first 100k chars) |
| D6 | Cilium docs: Hubble; Hubble README | https://docs.cilium.io/en/stable/observability/hubble/ , https://github.com/cilium/hubble | A (partial) |
| D7 | NSA/CISA Kubernetes Hardening Guidance v1.2 | https://media.defense.gov/2022/Aug/29/2003066362/1/1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF | C (403) |

## Candidate conditions for v2

| ID | Condition | Source | Priority |
|---|---|---|---|
| C1 | Recompute precision at realistic attack prevalence (no new data) | P3 | high |
| C2 | Multiple time windows for the fan-out rule (R4) to catch slow scans | P1 | high |
| C3 | Redefine sensitive-port list (R3) from the official K8s port table | D4 | high |
| C4 | Separate normal data used for learning vs evaluation | P4 | high |
| C5 | Merge duplicate alerts into incidents | P6 | medium |
| C6 | Sensitivity of the request-count rule (R5): k sigma, number of learning runs | P5 | medium |
| C7 | Failed-connection-ratio rule | P2 (confirm in full text) | medium |
| C8 | Map scenarios to ATT&CK techniques, fill gaps | D1, D2, D3 | medium |
| C9 | Add an environment with looser NetworkPolicy | D5, P7 | low |
| C10 | Check Hubble DNS/L7 visibility for the new-path rule (R2) | D6 | low |

## C1 numbers (computed from v1 results, TPR = 1.000)

precision = TPR*p / (TPR*p + FPR*(1-p))

| attack share p | default (FPR 39/40) | N=10 or scoped N=5 (FPR 17/40) |
|---|---|---|
| 2/3 (v1 mix) | 0.672 | 0.825 |
| 10% | 0.102 | 0.207 |
| 1% | 0.010 | 0.023 |
| 0.1% | 0.001 | 0.002 |
