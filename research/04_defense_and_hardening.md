# Research: LLM Defense, Hardening, and Vulnerability Detection

**Date:** 2026-02-20
**Query:** Comprehensive review of academic papers and technical publications on detecting, preventing, and mitigating prompt injection attacks against LLMs
**Confidence:** High
**Tools used:** Exa (12 queries), Brave (1 query, rate-limited), cross-referenced across 40+ sources

---

## Executive Summary

The field of LLM defense and hardening has matured rapidly since 2023, producing a layered taxonomy of defenses ranging from prompt-level engineering techniques to architectural privilege separation patterns. Research converges on the conclusion that **no single defense is sufficient**; effective protection requires defense-in-depth combining input/output guardrails, instruction hierarchy enforcement, architectural isolation, and continuous monitoring. The most promising recent work (2025-2026) shifts focus from model-level alignment to **system-level design patterns** that provide provable security guarantees regardless of model behavior. Standardized benchmarks (HarmBench, JailbreakBench) now enable reproducible measurement of attack success rates, while tools like Garak and Promptfoo operationalize vulnerability scanning in CI/CD pipelines.

---

## 1. Prompt Injection Detection

### 1.1 Classifier-Based Detection

#### Llama Guard (Meta, 2023)
- **Title:** "Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations"
- **Authors:** Hakan Inan, Kartikeya Upasani, Jianfeng Chi, Rashi Rungta, Krithika Iyer, Yuning Mao, Michael Tontchev, Qing Hu, Brian Fuller, Davide Testuggine, Madian Khabsa
- **Year:** 2023
- **Venue:** arXiv preprint (arXiv:2312.06674)
- **URL:** https://arxiv.org/abs/2312.06674
- **Key Findings:**
  - LLM-based input-output safeguard model using a safety risk taxonomy for both prompt classification and response classification
  - Based on Llama2-7b, instruction-tuned on a curated safety dataset
  - Performs multi-class classification with binary decision scores
  - Matches or exceeds performance of existing content moderation tools on OpenAI Moderation Evaluation dataset and ToxicChat benchmark
  - Supports zero-shot and few-shot prompting with customizable taxonomies
  - Later versions (Llama Guard 3, Llama Guard 4) expanded to 13+ risk categories with up to 86% reduction in violation rates
- **Defense Approach:** Dedicated LLM classifier operating as a pre/post-processing filter; functions independently of the primary application LLM
- **Relevance to Hardening Report:** Provides a reference architecture for input/output classification in a defense pipeline

#### InstructDetector (Wen et al., 2025)
- **Title:** "Defending against Indirect Prompt Injection by Instruction Detection"
- **Authors:** Tongyu Wen, Chenglong Wang, Xiyuan Yang, Haoyu Tang, Yueqi Xie, Lingjuan Lyu, Zhicheng Dou, Fangzhao Wu
- **Year:** 2025
- **Venue:** EMNLP 2025 Findings (also arXiv:2505.06311)
- **URL:** https://arxiv.org/abs/2505.06311 / https://aclanthology.org/2025.findings-emnlp.1060/
- **Key Findings:**
  - Novel detection method analyzing LLM behavioral states (hidden states and gradients in intermediate layers)
  - Achieves 99.60% detection accuracy in-domain, 96.90% out-of-domain
  - Reduces attack success rate to 0.03% on the BIPIA benchmark
  - Works by detecting whether external content contains embedded instructions
- **Defense Approach:** Behavioral analysis of LLM internal states to detect injected instructions in retrieved content
- **Relevance to Hardening Report:** Demonstrates that internal model signals can reliably distinguish data from instructions

#### PromptShield (Jacob et al., 2025)
- **Title:** "PromptShield: Deployable Detection for Prompt Injection Attacks"
- **Authors:** Dennis Jacob, Hend Alzahrani, Zhanhao Hu, Basel Alomair, David Wagner
- **Year:** 2025
- **Venue:** arXiv preprint (arXiv:2501.15145)
- **URL:** https://arxiv.org/abs/2501.15145
- **Key Findings:**
  - Benchmark for training and evaluating prompt injection detectors suitable for real-world deployment
  - Emphasizes carefully curated training data and larger models for enhanced performance
  - Focus on minimizing false positive rates for production viability
- **Defense Approach:** Trained classifier specifically targeting prompt injection detection with deployment-grade performance
- **Relevance to Hardening Report:** Addresses the practical deployment gap between research detectors and production systems

#### Microsoft Prompt Shields (Microsoft, 2025)
- **Title:** "How Microsoft defends against indirect prompt injection attacks"
- **Authors:** Andrew Paverd (Microsoft Security Response Center)
- **Year:** 2025
- **Venue:** Microsoft MSRC Blog
- **URL:** https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks
- **Key Findings:**
  - Multi-layered defense including Spotlighting, Prompt Shields detection, and Defender for Cloud integration
  - Preventative techniques: hardened system prompts, input isolation
  - Detection tools integrated with enterprise security monitoring
  - Impact mitigation: data governance, user consent workflows, deterministic blocking of exfiltration methods
- **Defense Approach:** Enterprise defense-in-depth combining preventative, detective, and mitigating controls
- **Relevance to Hardening Report:** Provides the most comprehensive real-world enterprise defense architecture documented publicly

### 1.2 Hybrid Real-Time Detection

#### Hybrid Multi-Layered Detection Framework (Prakash et al., 2026)
- **Title:** "Hybrid Real-time Framework for Detecting Adaptive Prompt Injection Attacks in Large Language Models"
- **Authors:** Chandra Prakash, Mary Lind, Elyson De La Cruz
- **Year:** 2026
- **Venue:** Journal of Computing Theories and Applications (JCTA)
- **URL:** https://publikasi.dinus.ac.id/jcta/article/download/15254/5830/54089
- **Key Findings:**
  - Three-layer architecture: heuristic pre-filtering, semantic analysis with fine-tuned transformer embeddings, behavioral pattern recognition
  - Achieved 97.4% accuracy, 100% precision, 95.0% recall
  - Specifically addresses adaptive attacks that evade single-layer defenses (e.g., DataFlip attacks against Known-Answer Detection)
- **Defense Approach:** Multi-layered detection pipeline operating in real-time
- **Relevance to Hardening Report:** Architecture pattern for production-grade detection combining speed (heuristic) with depth (semantic + behavioral)

---

## 2. Defense Mechanisms

### 2.1 Instruction Hierarchy

#### The Instruction Hierarchy (OpenAI, 2024)
- **Title:** "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions"
- **Authors:** OpenAI Research
- **Year:** 2024 (published April 19, 2024)
- **Venue:** OpenAI Research Publication
- **URL:** https://openai.com/index/the-instruction-hierarchy/
- **Key Findings:**
  - Core vulnerability: LLMs treat system prompts, user messages, and third-party content as equal priority
  - Proposes explicit priority hierarchy: system messages (highest) > user messages > third-party tool outputs (lowest)
  - Models trained to selectively ignore lower-privileged instructions when conflicts arise
  - Uses "context distillation" technique with synthetic training data
  - Applied to GPT-3.5: improved robustness against system prompt extraction by **up to 63%** and jailbreaking by **up to 30%**
  - First model to deploy this: GPT-4o Mini
  - Maintained standard performance on common benchmarks
- **Defense Approach:** Training-time intervention that teaches models to respect instruction privilege levels
- **Relevance to Hardening Report:** Foundational concept for any defense strategy -- establishes that instruction source provenance should determine priority

### 2.2 Spotlighting / Input Isolation

#### Spotlighting (Microsoft Research, 2024)
- **Title:** "Defending Against Indirect Prompt Injection Attacks With Spotlighting"
- **Authors:** Keegan Hines, Gary Lopez, Matthew Hall, Federico Zarfati, Yonatan Zunger, Emre Kiciman
- **Year:** 2024
- **Venue:** arXiv:2403.14720; also published at CEUR Workshop Proceedings Vol-3920
- **URL:** https://arxiv.org/abs/2403.14720
- **Key Findings:**
  - Family of prompt engineering techniques to improve LLMs' ability to distinguish among multiple input sources
  - Key insight: apply transformations to input that provide a reliable, continuous signal of provenance
  - Reduces indirect prompt injection attack success rate from **>50% to <2%** on GPT-family models
  - Minimal impact on underlying NLP task performance
  - Techniques include: data marking (adding provenance tags), encoding transformations, and delimiting strategies
- **Defense Approach:** Inference-time input transformation that marks untrusted content differently from trusted instructions
- **Relevance to Hardening Report:** Practical, immediately deployable defense requiring no model retraining; can be combined with other defenses

### 2.3 Boundary-Aware Defenses

#### BIPIA Benchmark and Defenses (Yi et al., 2023)
- **Title:** "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models"
- **Authors:** Jingwei Yi, Yueqi Xie, Bin Zhu, Emre Kiciman, Guangzhong Sun, Xing Xie, Fangzhao Wu
- **Year:** 2023 (revised 2025)
- **Venue:** arXiv:2312.14197
- **URL:** https://arxiv.org/abs/2312.14197
- **Key Findings:**
  - Introduces BIPIA benchmark for evaluating indirect prompt injection vulnerability
  - Finds all existing LLMs are universally vulnerable due to inability to differentiate informational context from actionable instructions
  - Proposes two defense mechanisms: **boundary awareness** and **explicit reminders**
  - Black-box defense (boundary awareness) significantly mitigates risks
  - White-box defense reduces attack success rate to **nearly zero** while maintaining output quality
- **Defense Approach:** Explicit boundary markers between trusted instructions and untrusted data, combined with in-context reminders
- **Relevance to Hardening Report:** Establishes the BIPIA benchmark as a standard evaluation target; boundary awareness is a simple, effective first-line defense

---

## 3. Guardrail Frameworks

### 3.1 NVIDIA NeMo Guardrails

#### NeMo Guardrails (NVIDIA, 2023)
- **Title:** "NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails"
- **Authors:** Traian Rebedea, Razvan Dinu, Makesh Sreedhar, Christopher Parisien, Jonathan Cohen
- **Year:** 2023
- **Venue:** EMNLP 2023 (arXiv:2310.10501)
- **URL:** https://arxiv.org/abs/2310.10501
- **GitHub:** https://github.com/NVIDIA-NeMo/Guardrails (5.6k stars, Apache 2.0)
- **Key Findings:**
  - Open-source toolkit for adding programmable guardrails to LLM-based conversational systems
  - Five rail types covering the full LLM interaction pipeline:
    1. **Input Rails:** Jailbreak detection, content moderation, topic control, PII masking
    2. **Dialog Rails:** Conversation flow enforcement, topic boundaries
    3. **Retrieval Rails:** Knowledge base result filtering
    4. **Execution Rails:** Tool/function call gating and validation
    5. **Output Rails:** Response validation, hallucination detection, sensitive data blocking
  - Uses **Colang**, a domain-specific language for defining conversational guardrails declaratively
  - Supports major LLM providers (OpenAI, Azure, HuggingFace) and frameworks (LangChain)
  - Enables runtime safety adjustments without model retraining
  - Latest release: v0.20.0 (January 2026)
- **Defense Approach:** Middleware safety layer intercepting LLM traffic with configurable policy enforcement
- **Relevance to Hardening Report:** Most comprehensive open-source guardrail framework; provides the implementation pattern for a defense pipeline

### 3.2 Adversarial Prompt Evaluation

#### Systematic Benchmarking of Guardrails (Zizzo et al., 2025)
- **Title:** "Adversarial Prompt Evaluation: Systematic Benchmarking of Guardrails Against Prompt Input Attacks on LLMs"
- **Authors:** Giulio Zizzo, Giandomenico Cornacchia, Kieran Fraser, Muhammad Zaid Hameed, Ambrish Rawat, Beat Buesser, Mark Purcell, Pin-Yu Chen, Prasanna Sattigeri, Kush Varshney
- **Year:** 2025
- **Venue:** arXiv:2502.15427
- **URL:** https://arxiv.org/abs/2502.15427
- **Key Findings:**
  - Systematically benchmarks **15 different defense mechanisms** against a wide range of malicious and benign datasets
  - Reveals significant performance variability among defenses depending on jailbreak type
  - **Critical finding:** Simple baseline defenses can perform competitively against many state-of-the-art defenses on current datasets
  - Highlights the need for diverse evaluation across attack types rather than single-benchmark claims
- **Defense Approach:** Meta-evaluation of guardrail effectiveness; provides methodology for defense selection
- **Relevance to Hardening Report:** Essential reference for selecting and evaluating guardrail strategies; demonstrates that defense effectiveness is highly context-dependent

---

## 4. Vulnerability Scanning and Testing Frameworks

### 4.1 Garak (NVIDIA)

- **Title:** Garak -- Generative AI Red-teaming & Assessment Kit
- **Authors:** NVIDIA (originally by Leon Derczynski)
- **Year:** 2023-present (continuously maintained)
- **URL:** https://github.com/NVIDIA/garak (6.8k stars, Apache 2.0)
- **Description:** Open-source LLM vulnerability scanner analogous to Nmap/Metasploit for network security
- **Key Capabilities:**
  - Tests for: hallucinations, data leakage, prompt injections, toxicity, jailbreak effectiveness, misinformation propagation
  - Uses static, dynamic, and adaptive probing techniques
  - Supports: Hugging Face Hub, Replicate, OpenAI API, LiteLLM, REST APIs, GGUF models
  - Generates JSONL reports documenting every probing attempt
  - Plugin architecture for custom probes and detectors
  - Can be integrated into CI/CD security testing pipelines
- **Defense Approach:** Proactive vulnerability identification through systematic adversarial probing
- **Relevance to Hardening Report:** Primary tool for automated security assessment; report output format is a model for hardening report structure

### 4.2 Promptfoo

- **Title:** Promptfoo -- LLM Red Team and Evaluation Platform
- **URL:** https://www.promptfoo.dev/
- **Key Capabilities:**
  - Automated red teaming with NIST AI RMF alignment
  - Risk scoring system based on CVSS principles (scores 0-10)
  - Vulnerability reports with severity classification and remediation guidance
  - Maps to OWASP Top 10 for LLMs
  - Supports custom evaluation plugins
- **Risk Scoring Components:**
  1. **Impact Base Score (0-4):** Critical/High/Medium/Low based on vulnerability type
  2. **Exploitability Modifier (0-4):** Based on Attack Success Rate (ASR)
  3. **Human Factor Modifier (0-1.5):** Complexity and ease of human exploitation
  4. **Complexity Penalty (0-0.5):** Additional penalty for easily exploitable vulnerabilities
- **Defense Approach:** Systematic evaluation and risk quantification for LLM applications
- **Relevance to Hardening Report:** Provides the most detailed public methodology for severity scoring and remediation prioritization -- directly applicable to hardening report generation

### 4.3 Spikee (Reversec)

- **Title:** Spikee -- Prompt Injection Testing Tool
- **URL:** Referenced at https://labs.reversec.com/posts/2025/08/design-patterns-to-secure-llm-agents-in-action
- **Description:** Open-source tool for testing prompt injection with many evasion techniques built in
- **Key Capability:** Tests the robustness of prompt injection defenses by applying various bypass techniques
- **Relevance to Hardening Report:** Useful for validating that deployed defenses withstand adaptive attacks

### 4.4 Framework for Rapid Defense Deployment (Swanda et al., 2025)

- **Title:** "A Framework for Rapidly Developing and Deploying Protection Against Large Language Model Attacks"
- **Authors:** Adam Swanda, Amy Chang, Alexander Chen, Fraser Burch, Paul Kassianik, Konstantin Berlin
- **Year:** 2025
- **Venue:** arXiv:2509.20639
- **URL:** https://arxiv.org/abs/2509.20639
- **Key Findings:**
  - Three-component defense system: Threat Intelligence System, Data Platform, Release Platform
  - Threat intelligence identifies emerging threats and translates to protective measures
  - Data platform aggregates/enriches data for observability + ML operations
  - Release platform enables safe, rapid updates to detection without disrupting workflows
  - Modeled on established malware protection patterns
- **Defense Approach:** Operational framework for continuously deploying and updating LLM defenses
- **Relevance to Hardening Report:** Provides the operational model for maintaining defenses over time, not just one-time assessment

---

## 5. Security Benchmarks

### 5.1 HarmBench

- **Title:** "HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal"
- **Authors:** Mantas Mazeika, Long Phan, Xuwang Yin, Andy Zou, Zifan Wang, Norman Mu, Elham Sakhaee, Nathaniel Li, Steven Basart, Bo Li, David Forsyth, Dan Hendrycks
- **Year:** 2024
- **Venue:** arXiv:2402.04249
- **URL:** https://arxiv.org/abs/2402.04249
- **GitHub:** https://github.com/centerforaisafety/HarmBench
- **Key Features:**
  - Standardized evaluation of **18 red teaming methods** against **33 target LLMs and defenses**
  - Curated datasets with expert annotations covering functional categories: standard prompts, contextual prompts, copyright-related prompts, multimodal inputs
  - Primary metrics: **Attack Success Rate (ASR)** and **Unsafe Response Rate (URR)**
  - Includes novel adversarial training method improving LLM robustness
  - Open-sourced framework enabling reproducible, multi-model comparison
  - De facto standard for quantitative LLM safety evaluation
- **Relevance to Hardening Report:** ASR and URR metrics are the foundation for measuring defense effectiveness in a hardening report

### 5.2 JailbreakBench

- **Title:** "JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models"
- **Authors:** Patrick Chao, Edoardo Debenedetti, Alexander Robey, Maksym Andriushchenko, Francesco Croce, Vikash Sehwag, Edgar Dobriban, Nicolas Flammarion, George J. Pappas, Florian Tramer, Hamed Hassani, Eric Wong
- **Year:** 2024
- **Venue:** arXiv:2404.01318 (also at NeurIPS / OpenReview)
- **URL:** https://arxiv.org/abs/2404.01318 / https://jailbreakbench.github.io/
- **Key Features:**
  - Components: (1) Repository of jailbreak artifacts, (2) JBB-Behaviors dataset (100 harmful + 100 benign behaviors), (3) Standardized evaluation framework with defined threat model, (4) Leaderboard tracking attacks/defenses
  - Defined threat model with specific system prompts, chat templates, and scoring functions
  - Tracks overrefusal rates alongside attack success
  - Aligned with OpenAI usage policies for behavior categorization
  - Open-sourced at https://github.com/JailbreakBench/jailbreakbench
- **Relevance to Hardening Report:** Provides standardized behavior sets and scoring methodology for consistent vulnerability assessment

### 5.3 AgentHarm

- **Title:** "AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents"
- **Authors:** Maksym Andriushchenko, Alexandra Souly, Mateusz Dziemian, Derek Duenas, Maxwell Lin, Justin Wang, Dan Hendrycks, Andy Zou, Zico Kolter, Matt Fredrikson, Eric Winsor, Jerome Wynne, Yarin Gal, Xander Davies
- **Year:** 2024
- **Venue:** arXiv:2410.09024
- **URL:** https://arxiv.org/abs/2410.09024
- **Key Features:**
  - **110 malicious agent tasks** across **11 harm categories** (fraud, cybercrime, harassment, etc.)
  - 440 total tasks with augmentations
  - Evaluates not just refusal but also execution capability after jailbreak
  - Key findings: many LLMs comply with malicious requests **even without jailbreaking**; simple jailbreak templates effectively compromise agents; successful jailbreaks enable coherent multi-step harmful tasks
- **Relevance to Hardening Report:** Critical for assessing agentic LLM deployments where tools amplify attack impact; demonstrates that agentic context significantly changes risk profile

### 5.4 PromptBench

- **Title:** "PromptBench: A Unified Library for Evaluation of Large Language Models"
- **Authors:** Kaijie Zhu, Qinlin Zhao, Hao Chen, Jindong Wang, Xing Xie
- **Year:** 2023/2024
- **Venue:** JMLR Volume 25 (2024); arXiv:2312.07910
- **URL:** https://arxiv.org/abs/2312.07910 / https://www.jmlr.org/papers/volume25/24-0023/24-0023.pdf
- **GitHub:** https://github.com/microsoft/promptbench
- **Key Features:**
  - Unified library for LLM evaluation including prompt construction, engineering, adversarial attack, and dynamic evaluation
  - Supports multiple evaluation tasks: sentiment analysis, grammar correctness, NLI, etc.
  - Incorporates adversarial attack methods for robustness testing
  - Developed at Microsoft Research Asia
- **Relevance to Hardening Report:** Provides programmatic framework for evaluating prompt robustness; can be integrated into automated testing pipelines

---

## 6. Architectural Defenses

### 6.1 Design Patterns for Securing LLM Agents

#### Design Patterns Paper (Beurer-Kellner et al., 2025)
- **Title:** "Design Patterns for Securing LLM Agents against Prompt Injections"
- **Authors:** Luca Beurer-Kellner, Beat Buesser, Ana-Maria Cretu, Edoardo Debenedetti, Daniel Dobos, Daniel Fabian, Marc Fischer, David Froelicher, Kathrin Grosse, Daniel Naeff, Ezinwanne Ozoani, Andrew Paverd, Florian Tramer, Vaclav Volhejn
- **Year:** 2025
- **Venue:** arXiv:2506.08837
- **URL:** https://arxiv.org/abs/2506.08837
- **Key Findings:**
  - Core thesis: prompt injection is an **architectural problem**, not a model problem
  - Proposes principled design patterns with **demonstrable security guarantees**
  - Key insight: once an LLM processes untrusted input, its capabilities must be architecturally restricted
  - "Security by Design" -- verifiable system design rather than relying on LLM alignment
  - Six design patterns analyzed with utility/security trade-offs
  - **Action Selector Pattern** identified as most secure: maps user queries to predefined actions, preventing feedback loops with tool outputs
  - Includes real-world case studies
- **Defense Approach:** Architectural constraints on LLM agent capabilities after processing untrusted content
- **Relevance to Hardening Report:** Most important paper for hardening recommendations -- shifts focus from "can we detect the attack?" to "does the architecture limit damage even if detection fails?"

### 6.2 Execution Isolation

#### IsolateGPT (Wu et al., 2024)
- **Title:** "IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems"
- **Authors:** Yuhao Wu, Franziska Roesner, Tadayoshi Kohno, Ning Zhang, Umar Iqbal
- **Year:** 2024 (revised 2025)
- **Venue:** arXiv:2403.04960
- **URL:** https://arxiv.org/abs/2403.04960
- **Key Findings:**
  - Proposes execution isolation framework for LLM applications supporting third-party apps
  - Addresses security/privacy risks from lack of isolation in current LLM ecosystems
  - Implements secure management of interactions between LLMs, apps, and system components
  - Less than 30% performance overhead for most queries
  - Effective against many security threats in non-isolated systems
- **Defense Approach:** Operating-system-style execution isolation applied to LLM agentic systems
- **Relevance to Hardening Report:** Provides formal isolation model analogous to process isolation in OS security

### 6.3 Privilege Separation

#### Type-Directed Privilege Separation (Jacob et al., 2025)
- **Title:** "Better Privilege Separation for Agents by Restricting Data Types"
- **Authors:** Dennis Jacob, Emad Alghamdi, Zhanhao Hu, Basel Alomair, David Wagner
- **Year:** 2025
- **Venue:** arXiv:2509.25926
- **URL:** https://arxiv.org/html/2509.25926v1
- **Key Findings:**
  - Proposes converting untrusted content to curated, restricted data types (not raw strings)
  - Each data type is limited in scope, eliminating the possibility of prompt injection
  - Unlike detectors/finetuning, this approach is **not vulnerable to adaptive attacks**
  - Maintains high utility across multiple case studies
  - Systematic prevention rather than probabilistic detection
- **Defense Approach:** Type-system-based privilege separation that eliminates prompt injection by construction
- **Relevance to Hardening Report:** Represents the theoretical ideal for defense -- architecturally impossible to inject rather than merely difficult

#### Progent (Shi et al., 2025)
- **Title:** "Progent: Programmable Privilege Control for LLM Agents"
- **Authors:** Tianneng Shi, Jingxuan He, Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo, Dawn Song
- **Year:** 2025
- **Venue:** arXiv:2504.11703
- **URL:** https://arxiv.org/abs/2504.11703
- **Key Findings:**
  - Framework for tool-level privilege control in LLM agents
  - Restricts agents to only necessary tool calls for specific user tasks
  - Domain-specific language for defining fine-grained security policies
  - Supports flexible fallback actions and dynamic policy updates
  - Deterministic runtime operation with **provable security guarantees**
  - **Reduces attack success rate to 0%** while maintaining agent utility and speed
  - LLMs can be leveraged to automatically generate effective security policies
- **Defense Approach:** Programmable, deterministic privilege control at the tool-call level
- **Relevance to Hardening Report:** Demonstrates that 0% ASR is achievable through architectural means; policy generation is automatable

### 6.4 Sandboxing Guidance

#### NVIDIA Sandboxing Guidance (2026)
- **Title:** "Practical Security Guidance for Sandboxing Agentic Workflows and Managing Execution Risk"
- **Authors:** Rich Harang (NVIDIA)
- **Year:** 2026
- **Venue:** NVIDIA Developer Blog
- **URL:** https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/
- **Key Findings:**
  - Primary threat: indirect prompt injection through malicious repos, PRs, git histories, `.cursorrules`, AGENT.md files, MCP responses
  - Manual approval leads to habituation where developers approve risky actions without scrutiny
  - Key controls:
    1. **Network egress controls:** Prevent unauthorized outbound connections (data exfiltration, reverse shells)
    2. **File write restrictions:** Block writes outside designated workspaces
    3. **Process isolation:** Limit agent execution environment
  - Organizations should tailor controls to risk tolerance
- **Defense Approach:** Operational sandboxing guidance for AI coding agents
- **Relevance to Hardening Report:** Practical, immediately actionable sandboxing recommendations for organizations deploying agentic AI

---

## 7. Standards and Frameworks

### 7.1 OWASP Top 10 for LLM Applications

- **Title:** "LLM01:2025 Prompt Injection"
- **URL:** https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- **Key Content:**
  - Prompt injection ranked as **#1 vulnerability** in OWASP LLM Top 10 for 2025
  - Defines direct and indirect prompt injection
  - Provides prevention and mitigation strategies
  - Maps to real-world attack scenarios
- **Relevance to Hardening Report:** Industry-standard risk classification; hardening reports should map findings to OWASP categories

### 7.2 NIST AI Risk Management Framework

- **Title:** "Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile"
- **Publication:** NIST AI 600-1 (July 2024)
- **URL:** https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- **Key Content:**
  - Four core functions: **Govern, Map, Measure, Manage**
  - Addresses GAI-specific risks including prompt injection
  - Provides structured risk assessment methodology
  - Mandates specific controls for prompt injection prevention and detection
  - Emphasizes identity/access management for AI agents
  - Promptfoo maps automated red teaming to the **Measure** function of NIST AI RMF
- **Relevance to Hardening Report:** Provides the regulatory/compliance framework within which hardening recommendations should be presented

### 7.3 AWS Bedrock Security Guidance

- **Title:** "Securing Amazon Bedrock Agents: A guide to safeguarding against indirect prompt injections"
- **Year:** 2025
- **URL:** https://aws.amazon.com/blogs/machine-learning/securing-amazon-bedrock-agents-a-guide-to-safeguarding-against-indirect-prompt-injections/
- **Key Content:**
  - Practical defense strategies for Bedrock Agents
  - Covers indirect prompt injection through documents, emails, websites
  - Comprehensive security controls and best practices
- **Relevance to Hardening Report:** AWS-specific guidance for teams deploying on Amazon Bedrock (relevant to hackathon context)

---

## 8. Monitoring and Observability

### 8.1 Production Monitoring Approaches

Based on multiple sources (Swept AI, Weights & Biases, Microsoft Defender for Cloud), the consensus monitoring architecture includes:

**Three Dimensions of LLM Observability:**

1. **Operational Observability:** Latency, throughput, error rates, token usage, cost tracking
2. **Quality Observability:** Semantic output quality, relevance scores, hallucination detection, coherence
3. **Safety Observability:** Prompt injection detection, policy violation monitoring, PII leakage, data exfiltration attempts

**Key Monitoring Signals for Attack Detection:**
- Anomalous input patterns (length, encoding, special characters)
- Deviation from expected output distributions
- Unusual tool call patterns or sequences
- Failed guardrail triggers (near-misses)
- Elevated refusal rates indicating probing
- Data exfiltration indicators (URLs, encoded data in outputs)
- Behavioral pattern changes over conversation sessions

**Production Tools Landscape:**
- **Microsoft Defender for Cloud:** Enterprise prompt shield integration with SIEM
- **Langfuse:** Open-source LLM observability with tracing, evaluation, prompt management
- **Weights & Biases Weave:** LLM monitoring with prompt/response logging
- **Swept AI:** Dedicated LLM observability platform
- **OpenTelemetry integrations:** For custom monitoring pipelines

### 8.2 Real-Time Protection Framework

The framework from Swanda et al. (2025, arXiv:2509.20639) proposes a three-component operational defense:

1. **Threat Intelligence:** Identifies emerging attack patterns, translates to detection rules
2. **Data Platform:** Aggregates telemetry, enriches with context, provides ML-ops for model updates
3. **Release Platform:** Enables rapid deployment of new defenses without service disruption

---

## 9. Attack Success Measurement and Severity Classification

### 9.1 Key Metrics

| Metric | Definition | Used By |
|--------|-----------|---------|
| **Attack Success Rate (ASR)** | Percentage of adversarial prompts that elicit harmful responses | HarmBench, JailbreakBench, most papers |
| **Unsafe Response Rate (URR)** | Rate at which model produces unsafe content under attack | HarmBench |
| **Defense Failure Rate** | Rate at which defense mechanisms fail to block attacks | Conformance AI |
| **Overrefusal Rate** | Rate of false positives (blocking benign requests) | JailbreakBench |
| **Severity Score** | Weighted measure of breach impact | Conformance AI, Promptfoo |

### 9.2 Promptfoo Risk Scoring Methodology (CVSS-Adapted)

The most detailed public scoring methodology for LLM vulnerabilities:

**Score Components (0-10 scale):**

| Component | Range | Description |
|-----------|-------|-------------|
| Impact Base Score | 0-4 | Potential business/security impact |
| Exploitability Modifier | 0-4 | Based on ASR |
| Human Factor Modifier | 0-1.5 | Ease of human exploitation |
| Complexity Penalty | 0-0.5 | Penalty for low-complexity exploits |

**Severity Categories:**

| Score | Severity | Example Vulnerabilities |
|-------|----------|----------------------|
| 8.0-10.0 | Critical | Data exfiltration, harmful content generation |
| 6.0-7.9 | High | Prompt injection, jailbreaking |
| 4.0-5.9 | Medium | Bias, misinformation |
| 0.0-3.9 | Low | Content quality issues |

### 9.3 Commercial Vulnerability Assessment (Conformance AI)

Real-world vulnerability assessment data from Conformance AI's 2025 report:

| Model | Vulnerability Rate | Severity Score |
|-------|-------------------|----------------|
| Claude Sonnet 3.5 | 20.8% | 18.8% |
| GPT-4o | 52.9% | 40.1% |
| Gemini 2.0 Flash | 74.7% | 64.4% |
| Llama 3.3 70B | 77.5% | 61.8% |
| DeepSeek-R1 | 84.1% | 74.1% |

Methodology: Three levels of increasing attack sophistication, each comprising hundreds of individual penetration tests.

### 9.4 Mapping to Real-World Impact

Based on OWASP LLM Top 10 and reviewed literature, vulnerabilities map to impact categories:

| Vulnerability Type | Real-World Impact | Risk Level |
|-------------------|-------------------|------------|
| Direct prompt injection | Unauthorized actions, data access | Critical |
| Indirect prompt injection | Data exfiltration, cross-user attacks | Critical |
| System prompt extraction | IP theft, attack surface exposure | High |
| Jailbreak (safety bypass) | Harmful content generation | High |
| Tool misuse via injection | Financial fraud, unauthorized transactions | Critical |
| PII leakage | Regulatory violations, privacy breaches | Critical |
| Hallucination exploitation | Misinformation, reputational damage | Medium |

---

## 10. Synthesis: Defense-in-Depth Architecture

Based on the literature review, the recommended defense architecture for a hardening report generator is:

```
Layer 1: INPUT GUARDRAILS
  - Prompt injection classifier (Llama Guard / PromptShield)
  - Input sanitization and encoding normalization
  - PII detection and masking
  - Length and format validation
  - Canary token insertion (for exfiltration detection)

Layer 2: MODEL-LEVEL DEFENSES
  - Instruction hierarchy enforcement
  - Spotlighting / data marking for untrusted content
  - System prompt hardening with boundary markers
  - Sandwich defense (repeat instructions after untrusted content)

Layer 3: ARCHITECTURAL CONTROLS
  - Privilege separation (Progent-style tool restrictions)
  - Type-directed data handling (Jacob et al.)
  - Execution isolation (IsolateGPT patterns)
  - Deterministic action validation
  - Human-in-the-loop for high-risk operations

Layer 4: OUTPUT GUARDRAILS
  - Response classification (Llama Guard)
  - Hallucination detection
  - Sensitive data filtering
  - URL/encoded content detection (exfiltration prevention)
  - Output format validation

Layer 5: MONITORING AND OBSERVABILITY
  - Real-time prompt injection detection
  - Behavioral anomaly detection
  - Audit logging of all LLM interactions
  - Alert pipelines for detected attacks
  - Threat intelligence integration
```

---

## 11. Comprehensive Source List

### Academic Papers

1. Inan et al. (2023) "Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations" -- arXiv:2312.06674 -- https://arxiv.org/abs/2312.06674 -- [Meta AI, Primary Source]
2. Wen et al. (2025) "Defending against Indirect Prompt Injection by Instruction Detection" -- EMNLP 2025 Findings / arXiv:2505.06311 -- https://arxiv.org/abs/2505.06311 -- [Academic, Primary Source]
3. Jacob et al. (2025) "PromptShield: Deployable Detection for Prompt Injection Attacks" -- arXiv:2501.15145 -- https://arxiv.org/abs/2501.15145 -- [Academic, Primary Source]
4. Hines et al. (2024) "Defending Against Indirect Prompt Injection Attacks With Spotlighting" -- arXiv:2403.14720 / CEUR-WS Vol-3920 -- https://arxiv.org/abs/2403.14720 -- [Microsoft Research, Primary Source]
5. Yi et al. (2023) "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models" -- arXiv:2312.14197 -- https://arxiv.org/abs/2312.14197 -- [Academic, Primary Source]
6. Rebedea et al. (2023) "NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails" -- EMNLP 2023 / arXiv:2310.10501 -- https://arxiv.org/abs/2310.10501 -- [NVIDIA, Primary Source]
7. Zizzo et al. (2025) "Adversarial Prompt Evaluation: Systematic Benchmarking of Guardrails Against Prompt Input Attacks on LLMs" -- arXiv:2502.15427 -- https://arxiv.org/abs/2502.15427 -- [IBM Research, Primary Source]
8. Mazeika et al. (2024) "HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal" -- arXiv:2402.04249 -- https://arxiv.org/abs/2402.04249 -- [CAIS/Academic, Primary Source]
9. Chao et al. (2024) "JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models" -- arXiv:2404.01318 -- https://arxiv.org/abs/2404.01318 -- [Academic, Primary Source]
10. Andriushchenko et al. (2024) "AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents" -- arXiv:2410.09024 -- https://arxiv.org/abs/2410.09024 -- [Academic, Primary Source]
11. Zhu et al. (2023) "PromptBench: A Unified Library for Evaluation of Large Language Models" -- JMLR Vol.25 / arXiv:2312.07910 -- https://arxiv.org/abs/2312.07910 -- [Microsoft Research, Primary Source]
12. Beurer-Kellner et al. (2025) "Design Patterns for Securing LLM Agents against Prompt Injections" -- arXiv:2506.08837 -- https://arxiv.org/abs/2506.08837 -- [ETH/Microsoft, Primary Source]
13. Wu et al. (2024) "IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems" -- arXiv:2403.04960 -- https://arxiv.org/abs/2403.04960 -- [Academic, Primary Source]
14. Jacob et al. (2025) "Better Privilege Separation for Agents by Restricting Data Types" -- arXiv:2509.25926 -- https://arxiv.org/html/2509.25926v1 -- [UC Berkeley, Primary Source]
15. Shi et al. (2025) "Progent: Programmable Privilege Control for LLM Agents" -- arXiv:2504.11703 -- https://arxiv.org/abs/2504.11703 -- [Academic, Primary Source]
16. Swanda et al. (2025) "A Framework for Rapidly Developing and Deploying Protection Against Large Language Model Attacks" -- arXiv:2509.20639 -- https://arxiv.org/abs/2509.20639 -- [Industry, Primary Source]
17. Prakash et al. (2026) "Hybrid Real-time Framework for Detecting Adaptive Prompt Injection Attacks in Large Language Models" -- JCTA -- https://publikasi.dinus.ac.id/jcta/article/download/15254/5830/54089 -- [Academic, Primary Source]
18. Seleznyov et al. (2025) "When Punctuation Matters: A Large-Scale Comparison of Prompt Robustness Methods for LLMs" -- arXiv:2508.11383 -- https://arxiv.org/abs/2508.11383 -- [Academic, Primary Source]

### Industry Publications & Standards

19. OpenAI (2024) "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions" -- https://openai.com/index/the-instruction-hierarchy/ -- [OpenAI, Primary Source]
20. NIST (2024) "AI 600-1: Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile" -- https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf -- [NIST, Primary Source]
21. OWASP (2025) "LLM01:2025 Prompt Injection" -- https://genai.owasp.org/llmrisk/llm01-prompt-injection/ -- [OWASP, Primary Source]
22. Microsoft MSRC (2025) "How Microsoft defends against indirect prompt injection attacks" -- https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks -- [Microsoft, Primary Source]
23. AWS (2025) "Securing Amazon Bedrock Agents: A guide to safeguarding against indirect prompt injections" -- https://aws.amazon.com/blogs/machine-learning/securing-amazon-bedrock-agents-a-guide-to-safeguarding-against-indirect-prompt-injections/ -- [AWS, Primary Source]
24. NVIDIA (2026) "Practical Security Guidance for Sandboxing Agentic Workflows and Managing Execution Risk" -- https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/ -- [NVIDIA, Primary Source]

### Tools & Frameworks

25. NVIDIA Garak -- https://github.com/NVIDIA/garak -- [6.8k stars, Apache 2.0]
26. NVIDIA NeMo Guardrails -- https://github.com/NVIDIA-NeMo/Guardrails -- [5.6k stars, Apache 2.0]
27. Promptfoo -- https://www.promptfoo.dev/ -- Risk Scoring: https://www.promptfoo.dev/docs/red-team/risk-scoring/
28. JailbreakBench -- https://jailbreakbench.github.io/ / https://github.com/JailbreakBench/jailbreakbench
29. HarmBench -- https://github.com/centerforaisafety/HarmBench
30. Microsoft PromptBench -- https://github.com/microsoft/promptbench
31. Reversec Spikee -- referenced at https://labs.reversec.com/posts/2025/08/design-patterns-to-secure-llm-agents-in-action

### Industry Reports & Assessments

32. Conformance AI (2025) "Commercial LLM Vulnerability Deep Dive" -- https://www.conformanceai.com/post/state-of-commercial-llms-vulnerability-assessment-report -- [Industry Assessment]

---

## 12. Open Questions and Research Gaps

1. **Adaptive attack resilience:** Most defenses are evaluated against static attack sets. Few papers demonstrate robustness against attackers who can iterate and adapt (except type-directed privilege separation which is immune by construction).

2. **Multi-modal injection:** As LLMs process images, audio, and video, injection through non-text modalities is under-studied. HarmBench includes some multimodal tests but this remains an open area.

3. **Cross-model transferability:** It is unclear how well defenses trained on one model family generalize to others. The Zizzo et al. (2025) paper specifically highlights high variability across defense types.

4. **False positive cost:** Most papers report detection accuracy but few quantify the business impact of false positives (blocked legitimate requests). This is critical for production deployment.

5. **Canary token approaches:** Despite being widely discussed in practitioner circles, peer-reviewed evaluation of canary token effectiveness for detecting data exfiltration through LLMs is sparse.

6. **Defense composition:** How multiple defense layers interact (whether they compound protection or create unexpected failure modes) is not well characterized.

7. **Latency overhead:** Production deployment requires sub-second guardrail latency. Many proposed defenses have not been benchmarked for inference-time overhead at scale.

---

## 13. Recommendations for Hardening Report Generator

Based on this research, a hardening report generator should:

1. **Adopt CVSS-adapted scoring** (Promptfoo methodology) for severity classification
2. **Map findings to OWASP LLM Top 10** and **NIST AI RMF** for regulatory alignment
3. **Measure using HarmBench/JailbreakBench metrics** (ASR, URR) for standardized comparison
4. **Report across all five defense layers** (input, model, architecture, output, monitoring)
5. **Include both ASR and overrefusal rate** to capture the defense/utility trade-off
6. **Provide tier-based remediation recommendations:**
   - Tier 1 (Immediate): Input validation, system prompt hardening, spotlighting
   - Tier 2 (Short-term): Guardrail deployment (NeMo/Llama Guard), output filtering
   - Tier 3 (Medium-term): Architectural redesign (privilege separation, action selectors)
   - Tier 4 (Ongoing): Monitoring pipeline, threat intelligence integration
7. **Use Garak/Promptfoo as the automated testing backend** for vulnerability scanning
8. **Generate actionable, prioritized findings** with specific code/configuration recommendations
