# AI_ANALYST_SPEC.md

**R3TRIVE AI Analyst Layer Specification**
Version: 1.0.0
Status: Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Model Support](#3-model-support)
4. [Context Builder](#4-context-builder)
5. [Prompt Engine](#5-prompt-engine)
6. [AI Capabilities](#6-ai-capabilities)
7. [Knowledge Base and RAG](#7-knowledge-base-and-rag)
8. [Model Router](#8-model-router)
9. [Response Parsing](#9-response-parsing)
10. [Privacy and Data Handling](#10-privacy-and-data-handling)
11. [Evaluation and Quality](#11-evaluation-and-quality)
12. [Configuration Reference](#12-configuration-reference)

---

## 1. Overview

The AI Analyst Layer augments human security analysts by providing natural-language explanations of threats, guided investigation assistance, attack chain reconstruction, and automated detection rule generation. It is designed to be useful even with smaller local models, and to gracefully degrade when AI is unavailable.

### 1.1 Design Constraints

- **No AI, no blindness.** Detection, alerting, and response must function entirely without AI. AI is augmentation, not a dependency.
- **Local-first.** All capabilities must be achievable with a locally-hosted Ollama model. Cloud AI is optional enhancement.
- **Privacy-preserving by default.** Sensitive host data is never sent to cloud APIs without explicit opt-in.
- **Actionable output.** AI responses must be structured enough to drive automated workflows, not just text for human reading.
- **Analyst-level expertise.** The AI persona is a senior SOC analyst, not a general assistant.

### 1.2 Capabilities Summary

| Capability | Command | AI Required |
|---|---|---|
| Incident explanation | `r3trive explain` | Yes |
| Activity summarization | `r3trive summarize` | Yes |
| Detection rule generation | `r3trive generate-rule` | Yes |
| Attack chain reconstruction | `r3trive attack-chain` | Yes |
| Free-form security query | `r3trive ask` | Yes |
| Response recommendation | Internal (on incident) | Yes |
| IOC extraction from text | Internal | Yes |
| False positive analysis | Internal | Yes |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       AI Analyst Layer                           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Request Handler                                         │   │
│  │  - Validates request type                                │   │
│  │  - Checks AI availability                                │   │
│  │  - Routes to appropriate capability handler              │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│     ┌───────────────────┼───────────────────────┐               │
│     ▼                   ▼                       ▼               │
│  ┌────────────┐  ┌─────────────────┐  ┌──────────────────┐      │
│  │  Context   │  │  Knowledge Base │  │  Conversation    │      │
│  │  Builder   │  │  (RAG / Vector) │  │  History Store   │      │
│  └─────┬──────┘  └────────┬────────┘  └────────┬─────────┘      │
│        │                  │                    │                 │
│        └──────────────────┴────────────────────┘                │
│                           │                                      │
│                           ▼                                      │
│              ┌────────────────────────┐                          │
│              │    Prompt Engine       │                          │
│              │  - System prompt       │                          │
│              │  - Context injection   │                          │
│              │  - Schema enforcement  │                          │
│              └────────────┬───────────┘                          │
│                           │                                      │
│                           ▼                                      │
│              ┌────────────────────────┐                          │
│              │    Model Router        │                          │
│              │  - Backend selection   │                          │
│              │  - Load balancing      │                          │
│              │  - Fallback logic      │                          │
│              └────────────┬───────────┘                          │
│                           │                                      │
│          ┌────────────────┼──────────────────────┐               │
│          ▼                ▼                      ▼               │
│   ┌─────────────┐  ┌────────────┐  ┌────────────────────┐       │
│   │  Ollama     │  │ OpenAI API │  │  Any OpenAI-compat │       │
│   │  (local)    │  │  (cloud)   │  │  (LM Studio, etc.) │       │
│   └─────────────┘  └────────────┘  └────────────────────┘       │
│                           │                                      │
│                           ▼                                      │
│              ┌────────────────────────┐                          │
│              │   Response Parser      │                          │
│              │  - JSON extraction     │                          │
│              │  - Schema validation   │                          │
│              │  - Hallucination check │                          │
│              └────────────────────────┘                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Model Support

### 3.1 Supported Backends

#### Ollama (Local)

Ollama runs open-source LLMs locally with GPU/CPU inference.

```yaml
ai:
  backend: ollama
  ollama:
    host: http://localhost:11434
    model: llama3.1:8b           # recommended minimum
    timeout: 60s
    num_ctx: 8192                # context window
```

Recommended models (ordered by capability vs. resource trade-off):

| Model | RAM Required | Speed | Quality |
|---|---|---|---|
| `llama3.1:70b` | 48GB | Slow (CPU) / Fast (GPU) | Excellent |
| `llama3.1:8b` | 8GB | Fast | Good |
| `mistral:7b` | 8GB | Fast | Good |
| `mixtral:8x7b` | 32GB | Medium | Very Good |
| `phi3:14b` | 12GB | Medium | Good |
| `deepseek-coder:6.7b` | 6GB | Fast | Good (code/rules) |

#### OpenAI API (Cloud)

```yaml
ai:
  backend: openai
  openai:
    api_key: "${OPENAI_API_KEY}"   # from environment
    model: gpt-4o
    timeout: 30s
    max_retries: 3
```

#### OpenAI-Compatible APIs

Any backend that implements the OpenAI `/v1/chat/completions` API:

```yaml
ai:
  backend: openai-compatible
  openai_compatible:
    base_url: https://api.together.xyz/v1
    api_key: "${TOGETHER_API_KEY}"
    model: meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo
```

### 3.2 Model Capability Requirements

The AI layer requires models capable of:
- Instruction following in structured (JSON) format
- Security domain knowledge (ATT&CK, common malware families, attack techniques)
- Logical reasoning across multi-event timelines
- Code generation (for rule generation capability)

Minimum viable model: 7B parameters, instruction-tuned, 4K+ context.

---

## 4. Context Builder

The Context Builder assembles all relevant information for a given AI request into a structured context object. This prevents the AI from making claims about data it hasn't been shown.

### 4.1 Context Object Schema

```json
{
  "request_type": "explain_incident",
  "timestamp": "2024-03-15T14:32:01Z",
  
  "incident": {
    "id": "INC-20240315-001",
    "name": "Credential Theft Campaign",
    "severity": "critical",
    "risk_score": 94.2,
    "host": { "hostname": "WORKSTATION-01", "os": "windows" },
    "timeline": [
      {
        "timestamp": "2024-03-15T14:30:01Z",
        "type": "alert",
        "rule": "R3T-EXEC-001",
        "summary": "PowerShell with encoded command spawned by winword.exe"
      },
      {
        "timestamp": "2024-03-15T14:30:15Z",
        "type": "alert",
        "rule": "R3T-CRED-001",
        "summary": "LSASS memory read from powershell.exe"
      }
    ],
    "attack_techniques": ["T1059.001", "T1003.001"],
    "artifacts": [
      {
        "type": "file",
        "path": "C:\\Users\\jsmith\\Downloads\\invoice.docm",
        "hash_sha256": "abc123...",
        "first_seen": "2024-03-15T14:29:55Z"
      }
    ]
  },
  
  "attack_context": {
    "T1059.001": {
      "name": "PowerShell",
      "tactic": "Execution",
      "description": "Adversaries may abuse PowerShell commands and scripts...",
      "mitigations": ["M1042", "M1049"]
    },
    "T1003.001": {
      "name": "LSASS Memory",
      "tactic": "Credential Access",
      "common_tools": ["Mimikatz", "ProcDump", "Cobalt Strike"]
    }
  },
  
  "host_context": {
    "recent_incidents": 0,
    "user": "jsmith",
    "user_role": "Finance",
    "asset_criticality": "medium"
  }
}
```

### 4.2 Context Prioritization

When context exceeds the model's token limit, the Context Builder prunes in this order (lowest priority removed first):

1. ~~Extended host history~~ (removed first)
2. ~~Low-severity related alerts~~ 
3. ~~Full ATT&CK technique descriptions~~ (truncated to summary)
4. ~~Older timeline events~~ (keep last 20)
5. ~~Artifact details~~
6. Core incident data (never removed)
7. User query (never removed)

### 4.3 Token Budget

| Component | Max Tokens |
|---|---|
| System prompt | 800 |
| Incident data | 2,000 |
| ATT&CK context | 800 |
| Host context | 400 |
| Conversation history | 1,000 |
| User query | 500 |
| Reserved for response | 1,500 |
| **Total** | **~7,000** |

Configurable via `ai.context.max_total_tokens`.

---

## 5. Prompt Engine

### 5.1 System Prompt

The system prompt establishes the AI's persona and behavioral constraints.

```
You are an expert cybersecurity analyst with 15 years of experience in 
incident response, threat hunting, and SOC operations. You specialize in 
Windows and Linux endpoint security, malware analysis, and MITRE ATT&CK.

Your role is to assist security analysts by:
- Explaining security incidents in clear, accurate terms
- Identifying attacker techniques and likely objectives
- Recommending specific, actionable response steps
- Generating detection rules when asked

STRICT RULES:
1. Only make claims supported by the data provided to you. Never invent 
   events, processes, IP addresses, or malware names that are not in the context.
2. Always cite which specific events or artifacts support your conclusions.
3. If you are uncertain, say so explicitly with a confidence level.
4. Use ATT&CK technique IDs when referencing attack techniques.
5. Response recommendations must be safe to execute — do not recommend 
   actions that could cause unintended harm (e.g., "delete all files").
6. Format structured output as valid JSON when requested.
```

### 5.2 Capability-Specific Prompts

Each capability has a task-specific prompt appended after the system prompt:

#### Incident Explanation Prompt

```
You have been given data about a security incident. Provide:
1. A 2-3 sentence executive summary suitable for a manager
2. A detailed technical analysis for the SOC analyst, including:
   - What happened (step by step, referencing the timeline)
   - What techniques the attacker used (ATT&CK IDs)
   - What the attacker likely intended to achieve
   - How confident you are in this assessment (0-100%)
3. Immediate response actions (ordered by priority)
4. Investigation leads (what else to look for)

Respond in the following JSON format:
{
  "executive_summary": "string",
  "technical_analysis": {
    "what_happened": "string",
    "techniques": [{"id": "T1059.001", "name": "...", "evidence": "..."}],
    "attacker_objective": "string",
    "confidence": 85
  },
  "response_actions": [
    {"priority": 1, "action": "string", "rationale": "string"}
  ],
  "investigation_leads": ["string"]
}
```

#### Rule Generation Prompt

```
Based on the incident data provided, generate a detection rule that would 
catch this specific attack behavior. Focus on behavioral indicators that 
are hard for attackers to evade, rather than IOCs that can easily be changed.

Generate a rule in R3TRIVE YAML format. The rule should:
- Target the most distinctive behavioral pattern in the incident
- Have reasonable conditions that won't cause excessive false positives
- Include a filter section to exclude common false positive sources
- Be set to the appropriate severity and confidence level

Respond with ONLY the YAML rule, no explanation outside the rule's description field.
```

#### Summarization Prompt

```
Summarize the security activity for the period provided. Include:
1. Overall threat level assessment
2. Top threats observed (if any)
3. Notable patterns or trends
4. Hosts or users of concern
5. Recommended analyst focus areas

Keep it concise — this is a shift handoff summary. Maximum 400 words.
Format as JSON:
{
  "threat_level": "low|medium|high|critical",
  "summary": "string",
  "top_threats": [{"name": "...", "count": N, "severity": "..."}],
  "patterns": ["string"],
  "focus_areas": ["string"]
}
```

---

## 6. AI Capabilities

### 6.1 Incident Explanation (`r3trive explain`)

**Input:** Incident ID or incident JSON file
**Output:** Structured explanation (see prompt schema above)

```bash
r3trive explain INC-20240315-001
r3trive explain INC-20240315-001 --format executive
r3trive explain incident.json --format technical
```

Example output (human-readable rendering of JSON response):

```
══════════════════════════════════════════════════════════════
 AI INCIDENT ANALYSIS — INC-20240315-001
 Confidence: 87%  |  Model: llama3.1:8b
══════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
─────────────────
A malicious Word document triggered a macro that launched PowerShell
to dump credentials from Windows memory. An attacker gained access to
domain credentials and likely attempted lateral movement.

WHAT HAPPENED
─────────────
14:29:55  Malicious document (invoice.docm) opened by user jsmith
14:30:01  Word macro executed PowerShell with encoded payload (T1059.001)
14:30:15  PowerShell read LSASS memory to extract credentials (T1003.001)
14:31:22  Encoded credentials transmitted to 185.220.101.47:443 (T1041)

ATTACKER OBJECTIVE
──────────────────
Credential theft for lateral movement within the domain. The Tor exit
node destination (185.220.101.47) suggests an external threat actor
rather than insider threat.

RESPONSE ACTIONS (Priority Order)
──────────────────────────────────
1. [IMMEDIATE] Isolate WORKSTATION-01 from the network
2. [IMMEDIATE] Reset password for jsmith and all accounts they access
3. [HIGH]      Revoke all active Kerberos tickets for jsmith
4. [HIGH]      Hunt for lateral movement from WORKSTATION-01 in last 2h
5. [MEDIUM]    Collect memory dump of powershell.exe (PID 12345) for forensics

INVESTIGATION LEADS
───────────────────
• Check email for invoice.docm delivery (likely phishing)
• Review VPN/RDP logs for jsmith in last 24h
• Search for 185.220.101.47 connections across all hosts
• Check for new scheduled tasks or services on WORKSTATION-01
```

### 6.2 Activity Summarization (`r3trive summarize`)

**Input:** Time period, optional host/severity filter
**Output:** Shift handoff summary

```bash
r3trive summarize --last 8h
r3trive summarize --last 24h --host WORKSTATION-01
r3trive summarize --since 2024-03-15T06:00:00Z --format executive
```

### 6.3 Detection Rule Generation (`r3trive generate-rule`)

**Input:** Incident ID, event JSON, or natural language description
**Output:** R3TRIVE YAML detection rule

```bash
r3trive generate-rule --from-incident INC-20240315-001
r3trive generate-rule --from-event evt_01HN2X --type behavioral
r3trive generate-rule --describe "PowerShell downloading files using BITS" --type behavioral
```

The generated rule is validated against the rule schema before output. Invalid rules are returned with error annotations.

### 6.4 Attack Chain Reconstruction (`r3trive attack-chain`)

**Input:** Incident ID or host + time range
**Output:** Structured kill chain with ATT&CK mapping

```bash
r3trive attack-chain INC-20240315-001
r3trive attack-chain --host WORKSTATION-01 --since 2024-03-15T14:00:00Z
```

Output format:
```json
{
  "kill_chain_phase": "credential_access",
  "steps": [
    {
      "step": 1,
      "timestamp": "2024-03-15T14:30:01Z",
      "technique": "T1059.001",
      "description": "PowerShell execution via macro",
      "evidence_event_ids": ["evt_001", "evt_002"]
    }
  ],
  "mitre_navigator_layer": { ... }
}
```

### 6.5 Free-Form Security Query (`r3trive ask`)

**Input:** Natural language question
**Output:** Natural language answer with citations to specific events/incidents

```bash
r3trive ask "Were there any lateral movement attempts in the last 24 hours?"
r3trive ask "What is the most suspicious process on WORKSTATION-01?"
r3trive ask "Is 185.220.101.47 associated with any known threat groups?"
r3trive ask "Generate a hunting query for Cobalt Strike beacon activity"
```

The AI has access to:
- Recent event/alert/incident data (via Context Builder)
- ATT&CK knowledge base
- Threat intelligence summaries (not raw IOC data sent to cloud)

---

## 7. Knowledge Base and RAG

### 7.1 Knowledge Base Contents

The local knowledge base (stored in vector DB) includes:

| Source | Content | Update Frequency |
|---|---|---|
| MITRE ATT&CK | All techniques, tactics, mitigations, groups | Monthly |
| R3TRIVE Rule Descriptions | Rule names, descriptions, references | On rule update |
| Malware Families | Common malware family descriptions, IOC patterns | Monthly |
| Threat Actor Profiles | APT group TTPs, targets, tooling | Monthly |
| Security Blogs | Curated analysis from major security vendors | Weekly |

### 7.2 RAG Pipeline

For queries that benefit from knowledge base lookup (e.g., "What is Cobalt Strike?"):

```
User Query
    │
    ▼
Query Embedding (local embedding model: nomic-embed-text)
    │
    ▼
Vector Similarity Search (top-k=5, threshold=0.75)
    │
    ▼
Retrieved Chunks (relevant ATT&CK/threat intel content)
    │
    ▼
Context Builder (injects retrieved chunks)
    │
    ▼
LLM with enriched context
```

### 7.3 Vector Store

Embeddings are stored in a local SQLite database using the `sqlite-vec` extension (zero external dependencies). For fleet deployments, a shared Qdrant or Chroma instance can be configured.

```yaml
ai:
  knowledge_base:
    vector_store: sqlite          # sqlite | qdrant | chroma
    embedding_model: nomic-embed-text
    embedding_backend: ollama
    chunk_size: 512
    chunk_overlap: 64
```

---

## 8. Model Router

The Model Router selects the appropriate backend for each request based on:
- Capability requirements (some tasks need larger models)
- Availability (failover)
- Privacy policy (some data must not leave the host)
- Cost optimization (simple queries use smaller/local models)

### 8.1 Routing Logic

```
Request arrives
    │
    ├── Privacy check: does request contain sensitive data?
    │     YES → must use local backend (Ollama)
    │     NO  → any backend allowed
    │
    ├── Task complexity assessment:
    │     SIMPLE (summarize, explain basic) → smallest available model
    │     COMPLEX (attack chain, rule gen)  → largest available model
    │
    └── Availability check:
          Primary backend available? → use it
          NO → try secondary
          NO → try tertiary
          NO → return "AI unavailable" gracefully
```

### 8.2 Backend Configuration

```yaml
ai:
  backends:
    - id: local-ollama
      type: ollama
      host: http://localhost:11434
      model: llama3.1:8b
      priority: 1                  # lower = higher priority
      privacy: strict              # this backend can receive all data
      
    - id: openai-cloud
      type: openai
      model: gpt-4o
      priority: 2
      privacy: redacted            # sensitive fields redacted before sending
      
  routing:
    sensitive_data_policy: local-only    # local-only | redacted | allow
    fallback_on_error: true
    timeout_per_backend: 30s
```

### 8.3 Data Redaction for Cloud Backends

When `privacy: redacted` is configured, the following fields are replaced before sending to cloud APIs:

| Field | Replacement |
|---|---|
| Hostnames | `HOST_<hash>` |
| Internal IP addresses | `IP_INTERNAL_<N>` |
| Usernames | `USER_<hash>` |
| File paths (non-system) | `PATH_<hash>` |
| Domain names (internal) | `DOMAIN_<hash>` |

Hashing is deterministic within a session (same value = same hash), preserving analytical relationships while anonymizing specifics.

---

## 9. Response Parsing

### 9.1 JSON Extraction

When structured output is required, the response parser:

1. Attempts to parse the entire response as JSON
2. If that fails: searches for JSON block between ` ```json ` and ` ``` `
3. If that fails: uses regex to extract JSON object from prose
4. If that fails: returns parse error, logs raw response for debugging

### 9.2 Schema Validation

Extracted JSON is validated against the expected schema for each capability. Fields missing from the response are filled with defaults or `null`. Schema violations above a threshold trigger a retry with clarified instructions.

### 9.3 Hallucination Detection

Basic hallucination checks are applied to AI responses:

- **Event ID check:** Any event IDs cited in the response are verified against the provided context. Invented IDs are flagged.
- **ATT&CK technique check:** Technique IDs cited must exist in the ATT&CK knowledge base.
- **Certainty calibration:** Responses claiming 100% confidence without strong evidence are downgraded.

Hallucination flags are included in the response metadata:

```json
{
  "response": { ... },
  "meta": {
    "model": "llama3.1:8b",
    "backend": "local-ollama",
    "latency_ms": 3420,
    "hallucination_flags": [],
    "tokens_used": 1842,
    "context_tokens": 3200
  }
}
```

---

## 10. Privacy and Data Handling

### 10.1 Data Classification

| Data Type | Default Policy | Cloud Allowed? |
|---|---|---|
| Event type and timestamp | Non-sensitive | Yes |
| ATT&CK technique IDs | Non-sensitive | Yes |
| External IP addresses (public) | Non-sensitive | Yes |
| Internal IP addresses | Sensitive | Redacted |
| Hostnames | Sensitive | Redacted |
| Usernames | Sensitive | Redacted |
| File contents / memory dumps | Highly sensitive | Never |
| Command line arguments | Sensitive | Redacted |
| Process paths (system) | Non-sensitive | Yes |
| Process paths (user files) | Sensitive | Redacted |

### 10.2 Audit Trail

Every AI request is logged with:
- Request type
- Backend used
- Whether data was redacted
- Token count
- Latency
- Requesting user

AI requests are NOT logged with their full content by default (to prevent sensitive data in logs). Enable with `ai.audit.log_requests: true` (for debugging only, not recommended in production).

---

## 11. Evaluation and Quality

### 11.1 Benchmark Suite

R3TRIVE includes a benchmark suite for evaluating AI response quality:

```bash
r3trive ai benchmark --suite standard
```

The benchmark evaluates:
- Accuracy of ATT&CK technique identification (against labeled dataset)
- Quality of generated rules (evaluated by rule engine syntax + specificity score)
- Response latency (p50, p95, p99)
- Hallucination rate (against known-correct context)

### 11.2 Quality Metrics

| Metric | Target |
|---|---|
| ATT&CK technique identification accuracy | > 85% |
| Generated rule syntax validity | > 95% |
| Hallucination rate | < 5% |
| Response latency p50 (local 8B model) | < 5s |
| Response latency p50 (cloud GPT-4o) | < 3s |
| Context utilization (citations to provided data) | > 70% |

### 11.3 Feedback Collection

Analysts can rate AI responses:

```bash
# After reviewing an AI explanation
r3trive feedback --request-id req_01HN2X --rating 4 --note "Good analysis, missed one lateral movement event"
```

Feedback is stored locally and used to tune prompts in future versions.

---

## 12. Configuration Reference

```yaml
ai:
  enabled: true
  
  # Backend configuration
  backends:
    - id: local
      type: ollama
      host: http://localhost:11434
      model: llama3.1:8b
      timeout: 60s
      priority: 1
      privacy: strict
      
    - id: cloud
      type: openai
      model: gpt-4o
      api_key: "${OPENAI_API_KEY}"
      timeout: 30s
      priority: 2
      privacy: redacted
  
  # Routing policy
  routing:
    sensitive_data_policy: local-only   # local-only | redacted | allow-all
    prefer_local: true
    fallback_on_error: true
    max_retries: 2
  
  # Context settings
  context:
    max_total_tokens: 7000
    max_timeline_events: 20
    include_attack_context: true
    include_host_context: true
    conversation_history_turns: 5
  
  # Knowledge base
  knowledge_base:
    enabled: true
    vector_store: sqlite
    db_path: "${DATA_DIR}/ai/knowledge.db"
    embedding_model: nomic-embed-text
    embedding_backend: local
    update_schedule: "0 2 * * 0"       # Weekly at 2am Sunday
  
  # Response settings
  response:
    validate_json: true
    hallucination_check: true
    max_response_tokens: 1500
  
  # Audit
  audit:
    log_requests: false
    log_responses: false
    log_metadata: true
    retention_days: 90
```

---

*End of AI_ANALYST_SPEC.md*
*Related: SYSTEM_ARCHITECTURE.md, API_REFERENCE.md, SOC_WORKFLOW.md*
