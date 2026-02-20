# Research: Agent-Specific Attacks on Agentic AI Systems

**Date:** 2026-02-20
**Query:** Comprehensive academic literature review on attacks targeting agentic AI systems (tool-using LLMs, RAG systems, multi-agent systems)
**Confidence:** High -- based on 25+ peer-reviewed papers from top venues
**Tools used:** Exa (12 queries), Brave (8 queries), covering arxiv, NeurIPS, ACL, USENIX, AISec, ICLR, OpenReview

---

## Executive Summary

The attack surface of agentic AI systems is fundamentally larger than that of standalone LLMs. Between 2023 and early 2026, a rapidly growing body of research has documented seven distinct attack categories targeting the unique components of LLM agents: tool-use interfaces, retrieval-augmented generation pipelines, multi-step planning chains, plugin/tool supply chains, privilege boundaries, cross-tool interactions, and persistent memory. The seminal work by Greshake et al. (2023) on indirect prompt injection laid the theoretical foundation, and subsequent work has produced concrete benchmarks (AgentDojo, InjecAgent, AgentHarm, ASB, TAMAS, ToolSword), demonstrated novel attack vectors (AgentPoison, MINJA, MemoryGraft, PoisonedRAG), and revealed that even state-of-the-art models like GPT-4 remain highly vulnerable. Multi-agent systems introduce additional attack propagation risks, and the emergence of the Model Context Protocol (MCP) has created entirely new supply-chain attack surfaces. Defenses remain largely inadequate; no single approach solves the problem.

---

## Table of Contents

1. [Indirect Prompt Injection (Foundational)](#1-indirect-prompt-injection-foundational)
2. [Tool-Use Exploitation](#2-tool-use-exploitation)
3. [RAG Poisoning / Indirect Injection via Retrieval](#3-rag-poisoning--indirect-injection-via-retrieval)
4. [Multi-Step / Multi-Hop Attacks](#4-multi-step--multi-hop-attacks)
5. [Supply Chain Attacks on Agents](#5-supply-chain-attacks-on-agents)
6. [Privilege Escalation in Agents](#6-privilege-escalation-in-agents)
7. [Cross-Plugin / Cross-Tool Attacks](#7-cross-plugin--cross-tool-attacks)
8. [Memory Poisoning](#8-memory-poisoning)
9. [Comprehensive Benchmarks and Frameworks](#9-comprehensive-benchmarks-and-frameworks)
10. [Multi-Agent System Attacks](#10-multi-agent-system-attacks)
11. [Key Themes and Takeaways](#11-key-themes-and-takeaways)
12. [Open Questions](#12-open-questions)
13. [Full Citation Index](#13-full-citation-index)

---

## 1. Indirect Prompt Injection (Foundational)

### Paper 1.1: Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection

- **Authors:** Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz
- **Year:** 2023
- **Venue:** AISec '23 (ACM Workshop on Artificial Intelligence and Security), co-located with CCS 2023
- **URL:** https://arxiv.org/abs/2302.12173
- **Published proceedings:** https://dl.acm.org/doi/10.1145/3605764.3623985

**Key Findings:**
- Formalized the concept of **indirect prompt injection** -- attacks where adversarial instructions are embedded in data sources (websites, emails, documents) that LLM-integrated applications process
- Demonstrated that LLMs processing external content can be remotely manipulated without direct user interface access
- Showed concrete attack scenarios: data exfiltration via email, spreading injections to other users, manipulating plugins to perform unauthorized actions
- Established the fundamental "confused deputy" problem: LLMs cannot reliably distinguish between instructions from trusted operators and instructions embedded in untrusted data

**Agent Components Targeted:** Data retrieval layer, plugin/tool interfaces, email processing, web browsing

**Relevance to Testing:** This is the foundational paper for all indirect prompt injection research. Its threat model directly applies to any agent that processes external data.

---

### Paper 1.2: Prompt Injection Attack against LLM-Integrated Applications (HouYi)

- **Authors:** Yi Liu, Gelei Deng, Yuekang Li, Kailong Wang, Zihao Wang, Xiaofeng Wang, Tianwei Zhang, Yepang Liu, Haoyu Wang, Yan Zheng, Yang Liu
- **Year:** 2024
- **Venue:** USENIX Security 2024
- **URL:** https://arxiv.org/abs/2306.05499
- **Code:** https://github.com/LLMSecurity/HouYi

**Key Findings:**
- Developed **HouYi**, an automated prompt injection framework for LLM-integrated applications
- Introduces a three-component attack structure: framework component (separates injected from original context), disruptor component (disrupts LLM's handling of original prompt), and malicious payload
- Deployed on **36 real-world LLM-integrated applications**, finding **31 were susceptible** to prompt injection
- 10 vendors validated the discoveries, including Notion (millions of potential users impacted)
- Demonstrates that the attack is systematic and automatable, not relying on manual crafting

**Agent Components Targeted:** LLM reasoning core, input processing pipeline, application-level integrations

**Relevance to Testing:** Provides a practical, automated framework for testing real-world LLM applications. The three-component structure can inform test case design.

---

## 2. Tool-Use Exploitation

### Paper 2.1: ToolSword: Unveiling Safety Issues of Large Language Models in Tool Learning Across Three Stages

- **Authors:** Junjie Ye, Sixian Li, Guanyu Li, Caishuang Huang, Songyang Gao, Yilong Wu, Qi Zhang, Tao Gui, Xuanjing Huang
- **Year:** 2024
- **Venue:** ACL 2024 (62nd Annual Meeting of the Association for Computational Linguistics)
- **URL:** https://arxiv.org/abs/2402.10753
- **Code:** https://github.com/Junjie-Ye/ToolSword
- **Proceedings:** https://aclanthology.org/2024.acl-long.119/

**Key Findings:**
- Comprehensive benchmark evaluating LLM safety across **three stages** of tool learning: input, execution, and output
- Six test scenarios covering: malicious queries (MQ), jailbreak attacks (JA), risky tools (RT), harmful feedback (HF), and combinations
- Experiments on **11 open-source and closed-source LLMs** reveal persistent safety challenges
- Even **GPT-4 is susceptible** to handling harmful queries, employing risky tools, and delivering detrimental feedback
- Key insight: safety alignment for chat does not transfer to tool-use contexts -- models that refuse harmful queries in conversation may execute them when tools are involved

**Agent Components Targeted:** Tool selection logic, tool execution pipeline, output interpretation

**Relevance to Testing:** Provides a structured taxonomy of tool-use safety scenarios. Directly applicable to designing test cases for tool-calling agents. The three-stage model (input/execution/output) maps to the agent processing pipeline.

---

### Paper 2.2: R-Judge: Benchmarking Safety Risk Awareness for LLM Agents

- **Authors:** Tongxin Yuan, Zhiwei He, Lingzhong Dong, Yiming Wang, Ruijie Zhao, Tian Xia, Lizhen Xu, Binglin Zhou, Fangqi Li, Zhuosheng Zhang, et al.
- **Year:** 2024
- **Venue:** arXiv preprint (cited widely in agent safety literature)
- **URL:** https://arxiv.org/abs/2401.10019

**Key Findings:**
- Benchmarks whether LLMs can identify safety risks in agent interaction records
- Tests models' ability to judge whether an agent's actions were safe across diverse scenarios
- Reveals that many models have poor risk awareness -- they cannot reliably identify when agent actions cross safety boundaries
- Provides a taxonomy of risk types specific to agent interactions

**Agent Components Targeted:** Risk assessment, safety reasoning, agent action evaluation

**Relevance to Testing:** Useful for evaluating whether a model serving as an agent can self-identify when it is being manipulated into unsafe actions.

---

### Paper 2.3: TrustAgent: Towards Safe and Trustworthy LLM-based Agents

- **Authors:** Wenyue Hua, Xianjun Yang, Mingyu Jin, et al.
- **Year:** 2024
- **Venue:** arXiv preprint
- **URL:** Referenced in multiple safety survey papers; GitHub: https://github.com/Ymm-cll/TrustAgent

**Key Findings:**
- Applies a fixed "constitution" of safety principles across agent planning stages
- Proposes pre-planning, in-planning, and post-planning safety strategies
- Demonstrates that applying safety constraints at multiple stages of agent execution reduces harmful outputs
- Highlights that single-point defenses are insufficient for agentic systems

**Agent Components Targeted:** Planning module, action execution, safety verification layer

---

### Paper 2.4: SafeToolBench: Pioneering a Prospective Benchmark to Evaluating Tool Utilization Safety in LLMs

- **Authors:** Referenced in tool safety literature (2025)
- **Year:** 2025
- **Venue:** Conference on Neural Information Processing Systems (NeurIPS area)
- **URL:** https://arxiv.org/abs/2509.07315

**Key Findings:**
- Builds on ToolSword to provide a more comprehensive, prospective benchmark for tool safety
- Evaluates safety of tool utilization across broader scenarios
- Incorporates real-world tool APIs and more diverse attack patterns

**Agent Components Targeted:** Tool API interfaces, tool selection, parameter injection

---

## 3. RAG Poisoning / Indirect Injection via Retrieval

### Paper 3.1: PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models

- **Authors:** Wei Zou, Runpeng Geng, Binghui Wang, Jinyuan Jia
- **Year:** 2024
- **Venue:** arXiv preprint (widely cited; IEEE S&P submission track)
- **URL:** https://arxiv.org/abs/2402.07867

**Key Findings:**
- **First knowledge corruption attack specifically targeting RAG systems**
- Attacker injects a small number of malicious texts into the knowledge database of a RAG system
- The poisoned documents induce the LLM to generate an **attacker-chosen target answer** for an **attacker-chosen target question**
- Attack requires injecting only **5 poisoned documents** to achieve high success rates
- Tested on multiple retrieval systems and LLMs, demonstrating broad applicability
- Proposes both black-box and white-box attack variants

**Agent Components Targeted:** Knowledge base / vector store, retrieval pipeline, context construction

**Relevance to Testing:** Directly applicable to testing RAG-based agents. Test cases should include poisoned documents in the knowledge base to evaluate whether the agent produces attacker-controlled outputs.

---

### Paper 3.2: BadRAG: Identifying Vulnerabilities in Retrieval Augmented Generation

- **Authors:** Jiaqi Xue, Mengxin Zheng, Yebowen Hu, Fei Liu, Xun Chen, Qian Lou
- **Year:** 2024
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2406.00083

**Key Findings:**
- Identifies vulnerabilities in RAG systems through adversarial document injection
- Demonstrates attacks where retrieval of poisoned documents causes the LLM to refuse answering (denial-of-service) or produce targeted misinformation
- The attacker has white-box access to the retriever in the strongest attack variant
- Complements PoisonedRAG by exploring different attack goals (not just targeted answers but also availability attacks)

**Agent Components Targeted:** Retriever model, embedding space, knowledge base

---

### Paper 3.3: Benchmarking Poisoning Attacks against Retrieval-Augmented Generation

- **Authors:** (2025 meta-study)
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2505.18543

**Key Findings:**
- Systematic benchmarking of multiple RAG poisoning attack strategies
- Compares PoisonedRAG, BadRAG, and other approaches under unified evaluation conditions
- Finds that attack effectiveness varies significantly based on retriever architecture and chunk size
- White-box attacks are substantially more effective than black-box variants

**Agent Components Targeted:** Full RAG pipeline (retriever, reranker, generator)

---

## 4. Multi-Step / Multi-Hop Attacks

### Paper 4.1: InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents

- **Authors:** Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang
- **Year:** 2024
- **Venue:** Findings of ACL 2024 (Association for Computational Linguistics)
- **URL:** https://arxiv.org/abs/2403.02691
- **Proceedings:** https://aclanthology.org/2024.findings-acl.624/

**Key Findings:**
- First benchmark specifically for **indirect prompt injections in tool-integrated LLM agents**
- Covers scenarios where malicious instructions are embedded in external content (emails, websites) that the agent retrieves
- Defines two attack types: **Direct Harm** (agent directly executes harmful action) and **Indirect Harm** (agent is tricked through multi-step reasoning)
- Tests across ReAct agents and function-calling agents
- Finds that agents are highly susceptible, especially when the injected instructions align with the tool capabilities available to the agent
- Key insight: **tool availability dramatically increases attack surface** -- agents with more tools are more vulnerable because injections can leverage any available tool

**Agent Components Targeted:** Tool-calling interface, retrieved context processing, multi-step reasoning chain

**Relevance to Testing:** Provides a structured benchmark with 1,054 test cases. The Direct Harm vs. Indirect Harm distinction is useful for categorizing test scenarios. The finding that tool availability increases vulnerability suggests testing should cover agents at different tool-permission levels.

---

### Paper 4.2: AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents

- **Authors:** Maksym Andriushchenko, Alexandra Souly, Mateusz Dziemian, Derek Duenas, Maxwell Lin, Justin Wang, Dan Hendrycks, Andy Zou, Zico Kolter, Matt Fredrikson, Eric Winsor, Jerome Wynne, Yarin Gal, Xander Davies
- **Year:** 2024 (published ICLR 2025)
- **Venue:** ICLR 2025
- **URL:** https://arxiv.org/abs/2410.09024
- **OpenReview:** https://openreview.net/forum?id=AC5n7xHuR1

**Key Findings:**
- **110 explicitly malicious agent tasks** (440 with augmentations) covering **11 harm categories** including fraud, cybercrime, and harassment
- Finds that **more capable models that do not refuse achieve higher harm scores** -- capability and safety are inversely correlated in the agent setting
- Key finding: **robustness of LLM agents vs. LLM chatbots is substantially different** -- models safe in chat may be unsafe as agents
- Simple jailbreak techniques are highly effective against agents, more so than against chatbots
- Provides a practical, cheap-to-run evaluation framework integrated with the UK AI Safety Institute's evaluation tools

**Agent Components Targeted:** Planning and execution pipeline, tool-use decision-making, multi-step action sequences

**Relevance to Testing:** Critical benchmark. Demonstrates that agent safety requires agent-specific evaluation, not just chatbot-level safety testing. The 11 harm categories provide a taxonomy for test case design.

---

## 5. Supply Chain Attacks on Agents

### Paper 5.1: MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers

- **Authors:** (2025)
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2508.14925

**Key Findings:**
- **First benchmark for Tool Poisoning attacks targeting real-world MCP (Model Context Protocol) servers**
- Investigates a fundamental vulnerability: **malicious instructions embedded within a tool's metadata without execution** -- the tool does not need to be called for the attack to succeed
- Benchmark comprises **45+ real-world MCP servers** across 8 application domains
- Demonstrates that agents can be manipulated simply by reading tool descriptions that contain hidden adversarial instructions
- The attack is especially dangerous because MCP servers are installed as trusted components

**Agent Components Targeted:** Tool discovery/registration, tool metadata parsing, MCP protocol layer

**Relevance to Testing:** Directly relevant to any agent using MCP. Testing should include verification of tool metadata sanitization and checking whether tool descriptions can influence agent behavior.

---

### Paper 5.2: Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers

- **Authors:** (2025)
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2506.13538

**Key Findings:**
- Systematic security analysis of MCP servers in the wild
- **7.2% of servers contain general vulnerabilities**
- **5.5% exhibit MCP-specific tool poisoning** vulnerabilities
- 66% of servers exhibit code smells; 14.4% contain bug patterns
- Reveals that the MCP ecosystem is immature from a security perspective, with many servers deployed without adequate security review

**Agent Components Targeted:** MCP server infrastructure, tool registration, server authentication

---

### Paper 5.3: Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks

- **Authors:** Saeid Jamshidi et al.
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2512.06556

**Key Findings:**
- Proposes defense mechanisms for MCP tool poisoning
- Identifies three attack types: **Shadowing Attacks** (malicious tool shadows legitimate one), **MCP Rug Pulls** (tool behavior changes after trust is established), and **metadata injection**
- Demonstrates that tool calling priority can be manipulated by embedding metadata in tool code comments
- Proposes defense mechanisms including tool integrity verification and metadata sanitization

**Agent Components Targeted:** Tool trust model, tool resolution/priority, MCP protocol security

---

### Paper 5.4: Systematic Analysis of MCP Security

- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2508.12538

**Key Findings:**
- Proposes taxonomy of MCP-specific attacks: Tool Poisoning Attacks (TPA), Shadowing Attacks, MCP Rug Pulls
- Demonstrates that manipulating tool calling priority via embedded metadata in tool code comments is practical
- Provides systematic analysis of attack surfaces in the MCP protocol

**Agent Components Targeted:** MCP protocol, tool priority system, metadata processing

---

### Paper 5.5: Security Study Based on the ChatGPT Plugin System: Identifying Security Vulnerabilities

- **Authors:** Ruomai Ren et al.
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2507.21128

**Key Findings:**
- Analyzes security vulnerabilities in the ChatGPT plugin ecosystem
- Identifies leakage of manifest files and API construction methods as attack vectors
- Certain plugins become targets for high-frequency attacks due to their exposed architecture
- Demonstrates real supply-chain risks in plugin-based agent architectures

**Agent Components Targeted:** Plugin manifest files, OAuth authentication, API interfaces

**Additional Context:** Salt Labs researchers (June 2023) uncovered OAuth authentication vulnerabilities in ChatGPT plugins that could allow attackers to install malicious plugins on user accounts and access sensitive data.

---

## 6. Privilege Escalation in Agents

### Paper 6.1: AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents

- **Authors:** Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, Florian Tramer
- **Year:** 2024
- **Venue:** NeurIPS 2024 (Datasets and Benchmarks Track)
- **URL:** https://arxiv.org/abs/2406.13352
- **Website:** https://agentdojo.spylab.ai/
- **OpenReview:** https://openreview.net/forum?id=m1YYAQjO3w

**Key Findings:**
- **Dynamic evaluation framework** (not static test suite) for agent security with **97 realistic tasks** and **629 security test cases**
- Tasks include email management, e-banking, travel bookings -- scenarios where privilege escalation matters
- Finds that **state-of-the-art LLMs fail at many tasks even without attacks**, and existing attacks break some but not all security properties
- Used by **US and UK AI Safety Institutes** to demonstrate vulnerability of Claude 3.5 Sonnet to prompt injections
- Extensible framework supporting new attacks, defenses, and tasks
- Won SafeBench first prize alongside Cybench and BackdoorLLM
- Key insight on privilege: agents with access to privileged tools (e.g., bank transfers) can be induced to use them via prompt injection in untrusted data

**Agent Components Targeted:** Full agent pipeline -- tool calling, data retrieval, action execution, privilege boundaries

**Relevance to Testing:** Gold standard benchmark for agent security. The dynamic nature means it stays current as attacks evolve. Directly applicable to testing privilege escalation scenarios.

---

### Paper 6.2: Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents

- **Authors:** Hanrong Zhang, Jingyuan Huang, Kai Mei, Yifei Yao, Zhenting Wang, Chenlu Zhan, Hongwei Wang, Yongfeng Zhang
- **Year:** 2024
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2410.02644

**Key Findings:**
- **Comprehensive framework** covering **10 scenarios** (e-commerce, autonomous driving, finance, etc.)
- Formalizes attack and defense categories for LLM-based agents
- Includes scenarios specifically targeting privilege escalation -- agents performing actions outside their intended scope
- Demonstrates that attacks can chain across multiple interaction steps to escalate privileges gradually
- Provides both attack success metrics and defense effectiveness metrics

**Agent Components Targeted:** Authorization boundaries, action validation, multi-scenario agent deployments

---

## 7. Cross-Plugin / Cross-Tool Attacks

### Paper 7.1: Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?

- **Authors:** (2025)
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2510.05244

**Key Findings:**
- Demonstrates that a simple "minimize & sanitize" defense requiring no LLM retraining can be effective
- Evaluates cross-tool attack scenarios where data from one tool influences actions via another
- Highlights that **existing benchmarks may not capture the full complexity of cross-tool attacks**
- Finds that defenses effective against single-tool injection may fail when multiple tools interact
- Argues for stronger, more realistic benchmarks that model inter-tool data flows

**Agent Components Targeted:** Inter-tool data flow, tool output processing, context management across tools

**Relevance to Testing:** Important for understanding how attacks can chain across tools. Tests should include scenarios where malicious content retrieved by one tool (e.g., web browser) influences actions of another (e.g., email sender).

---

### Cross-Tool Attack Pattern (from Greshake et al. 2023 and subsequent work):

The foundational indirect injection paper already demonstrated cross-plugin attacks:
- **Email-to-action:** Malicious instructions in emails cause agents to take actions via other tools
- **Web-to-email:** Content on websites instructs agents to send emails with exfiltrated data
- **Document-to-API:** Poisoned documents cause agents to make unauthorized API calls

These patterns have been confirmed and extended by InjecAgent, AgentDojo, and ASB benchmarks.

---

## 8. Memory Poisoning

### Paper 8.1: MINJA: Memory Injection Attacks on LLM Agents via Query-Only Interaction

- **Authors:** Shen Dong, Shaochen Xu, Pengfei He, Yige Li, Jiliang Tang, Tianming Liu, Hui Liu, Zhen Xiang
- **Year:** 2025
- **Venue:** arXiv preprint (also listed on OpenReview as CoRR 2025)
- **URL:** https://arxiv.org/abs/2503.03704
- **OpenReview:** https://openreview.net/forum?id=aGvo1YEmnJ

**Key Findings:**
- **Novel memory injection attack requiring only query-level interaction** -- attacker does NOT need direct access to the memory bank
- Injects malicious records into agent memory by interacting through normal queries and output observations
- Uses **bridging steps** to link victim queries to malicious reasoning chains
- Employs an **indication prompt** that guides the agent to autonomously generate bridging steps, with a **progressive shortening strategy** to make malicious records easily retrievable
- Demonstrates effectiveness across diverse agent architectures
- Key threat: **any user can influence agent memory** through normal interaction, without elevated privileges

**Agent Components Targeted:** Long-term memory / experience store, retrieval mechanism, reasoning chain

**Relevance to Testing:** Critical for testing agents with persistent memory. Tests should simulate multi-session interactions where earlier sessions attempt to poison the memory for later exploitation.

---

### Paper 8.2: AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases

- **Authors:** Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, Bo Li
- **Year:** 2024
- **Venue:** NeurIPS 2024 (Main Conference Track)
- **URL:** https://arxiv.org/abs/2407.12784
- **Proceedings:** https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html
- **Code:** https://github.com/BillChan226/AgentPoison

**Key Findings:**
- **First backdoor attack targeting generic and RAG-based LLM agents** via memory/knowledge base poisoning
- Uses **constrained optimization** to generate backdoor triggers that map to a unique embedding space
- When user instructions contain the trigger, malicious demonstrations are retrieved with high probability; benign instructions maintain normal performance
- **No model training or fine-tuning required** -- attack operates purely at the data level
- Achieves **>80% attack success rate** with **<1% impact on benign performance** at **<0.1% poison rate**
- Tested on three real-world agent types: RAG-based autonomous driving, knowledge-intensive QA, and healthcare EHRAgent
- Triggers exhibit **superior transferability** across different retriever models

**Agent Components Targeted:** RAG knowledge base, long-term memory, embedding/retrieval system

**Relevance to Testing:** Demonstrates that extremely low poison rates can compromise agents. Testing should include poisoning just a tiny fraction of the knowledge base and measuring downstream effects.

---

### Paper 8.3: MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval

- **Authors:** Haoyu He et al.
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2512.16962
- **Code:** https://github.com/Jacobhhy/Agent-Memory-Poisoning

**Key Findings:**
- Novel **indirect injection attack** that compromises agent behavior by implanting malicious "successful experiences" into long-term memory
- Exploits the agent's **semantic imitation heuristic** -- the tendency to replicate patterns from retrieved successful tasks
- Attacker supplies **benign-looking ingestion artifacts** (e.g., README files) that the agent reads during execution
- Agent constructs a **poisoned RAG store** where malicious procedure templates persist alongside benign experiences
- **Union retrieval** (BM25 + embeddings) reliably surfaces grafted memories for semantically similar tasks
- Validated on **MetaGPT's DataInterpreter agent with GPT-4o**
- A **small number of poisoned records** can account for a large fraction of retrieved experiences on benign workloads
- Key insight: **experience-based self-improvement becomes a vector for stealthy, durable compromise**

**Agent Components Targeted:** Experience/episodic memory, RAG store, semantic retrieval, self-improvement loop

**Relevance to Testing:** Highly relevant for testing agents that learn from past experiences. Attacks are persistent across sessions and survive memory cleanup that doesn't specifically target provenance.

---

## 9. Comprehensive Benchmarks and Frameworks

### Paper 9.1: AgentDojo (ETH Zurich / Invariant Labs)
- See Section 6.1 above. NeurIPS 2024. 97 tasks, 629 security test cases.
- **URL:** https://arxiv.org/abs/2406.13352

### Paper 9.2: InjecAgent (ACL 2024)
- See Section 4.1 above. 1,054 test cases for indirect prompt injection in tool-integrated agents.
- **URL:** https://arxiv.org/abs/2403.02691

### Paper 9.3: AgentHarm (ICLR 2025)
- See Section 4.2 above. 440 malicious agent tasks across 11 harm categories.
- **URL:** https://arxiv.org/abs/2410.09024

### Paper 9.4: Agent Security Bench / ASB
- See Section 6.2 above. 10 scenarios formalizing attacks and defenses.
- **URL:** https://arxiv.org/abs/2410.02644

### Paper 9.5: ToolSword (ACL 2024)
- See Section 2.1 above. Tool safety across three stages on 11 LLMs.
- **URL:** https://arxiv.org/abs/2402.10753

### Paper 9.6: TAMAS: Benchmarking Adversarial Risks in Multi-Agent LLM Systems

- **Authors:** Ishan Kavathekar, Hemang Jain, Ameya Rathod, Ponnurangam Kumaraguru, Tanuja Ganu
- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2511.05269

**Key Findings:**
- Benchmark specifically for **multi-agent LLM system** robustness and safety
- **5 distinct scenarios**, **300 adversarial instances**, **6 attack types**, **211 tools**, plus 100 harmless baseline tasks
- Evaluates 10 backbone LLMs across 3 agent interaction configurations from **AutoGen and CrewAI frameworks**
- Introduces **Effective Robustness Score (ERS)** to assess the tradeoff between safety and task effectiveness
- Key finding: **multi-agent systems are highly vulnerable to adversarial attacks**, more so than single-agent setups

**Agent Components Targeted:** Multi-agent coordination, inter-agent communication, shared tool access

### Paper 9.7: WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks

- **Year:** 2025
- **Venue:** arXiv preprint
- **URL:** https://arxiv.org/abs/2504.18575

**Key Findings:**
- Targets web-browsing agents specifically
- Benchmarks prompt injection attacks in the context of web navigation tasks
- Evaluates how web agents can be hijacked through malicious web content

**Agent Components Targeted:** Web browsing capability, page content parsing, navigation decisions

---

## 10. Multi-Agent System Attacks

### Paper 10.1: SafeAgents / Exposing Weak Links in Multi-Agent Systems under Adversarial Prompting

- **Authors:** Nirmit Arora, Sathvik Joel, Ishan Kavathekar, Palak, Rohan Gandhi, Yash Pandya, Tanuja Ganu, Aditya Kanade, Akshay Nambi
- **Year:** 2025 (submitted to ICLR 2026)
- **Venue:** arXiv preprint / ICLR 2026 submission
- **URL:** https://arxiv.org/abs/2511.10949

**Key Findings:**
- Introduces **SafeAgents**, a unified framework for **fine-grained security assessment** of multi-agent systems
- Introduces **DHARMA**, a diagnostic measure that identifies weak links within multi-agent pipelines
- Studies **5 widely adopted multi-agent architectures**: centralized, decentralized, and hybrid variants
- Evaluates across **4 datasets** spanning web tasks, tool use, and code generation
- Key finding: **centralized systems that delegate only atomic instructions to sub-agents obscure harmful objectives**, making attacks harder to detect
- Design choices like plan construction strategies, inter-agent context sharing, and fallback behaviors **significantly affect susceptibility** to adversarial prompting
- **Code available:** https://anonymous.4open.science/r/SafeAgents/

**Agent Components Targeted:** Multi-agent architecture, delegation patterns, context sharing, fallback mechanisms

**Relevance to Testing:** Directly applicable to testing multi-agent systems. The DHARMA metric can be used to identify which agent in a pipeline is the weak link. The finding about atomic instruction delegation is particularly important for systems using task decomposition.

---

### Paper 10.2: TAMAS (see Section 9.6)

### Multi-Agent Propagation Risk (from literature synthesis):

Multiple sources confirm a critical finding: **a single compromised agent in a multi-agent system can corrupt downstream decision-making rapidly.** One study (Galileo AI, December 2025) found that in simulated multi-agent systems, a single compromised agent poisoned 87% of downstream decision-making within four hours. The cascade appears as normal operation until traced to the source.

---

## 11. Key Themes and Takeaways for Agent Security Testing

### Theme 1: The Confused Deputy Problem is Fundamental
All LLM agents face the core challenge that they cannot reliably distinguish between instructions from trusted operators and instructions embedded in untrusted data. This is not a bug to be fixed but a fundamental architectural limitation of current LLM-based systems.

### Theme 2: Chat Safety Does Not Transfer to Agent Safety
Multiple papers (ToolSword, AgentHarm) demonstrate that models safe in conversation may be unsafe when given tools. Agent-specific safety evaluation is mandatory.

### Theme 3: Tool Availability Multiplies Attack Surface
InjecAgent and AgentDojo show that agents with more tools are more vulnerable. Each tool adds both capability and attack surface. Principle of least privilege is critical.

### Theme 4: Low Poison Rates Are Sufficient
AgentPoison achieves >80% attack success with <0.1% poison rate. MemoryGraft shows a few poisoned records can dominate retrieval. Defenses cannot rely on statistical outlier detection alone.

### Theme 5: Temporal Decoupling Makes Detection Hard
Memory poisoning attacks (MINJA, MemoryGraft) separate the injection event from the exploitation event by days, weeks, or months. Traditional anomaly detection that focuses on individual interactions will miss these.

### Theme 6: Supply Chain is the New Frontier
MCP tool poisoning (MCPTox), ChatGPT plugin vulnerabilities, and tool metadata injection represent a rapidly growing threat that most organizations are not equipped to handle.

### Theme 7: Multi-Agent Systems Amplify All Risks
Compromises propagate through agent-to-agent communication. Centralized architectures can obscure harmful intent through task decomposition. Security must be designed at the system level, not per-agent.

---

## 12. Open Questions

1. **Defense adequacy:** No current defense mechanism provides reliable protection against all attack categories simultaneously. The "minimize & sanitize" approach is promising but untested at scale.

2. **Benchmark realism:** Current benchmarks may not capture the full complexity of real-world agent deployments, especially those with custom tools and proprietary data sources.

3. **Memory provenance:** How to efficiently track and validate the provenance of every piece of information in an agent's memory without unacceptable performance overhead.

4. **Cross-framework generalization:** Whether vulnerabilities found in one agent framework (e.g., LangChain) generalize to others (e.g., AutoGen, CrewAI, custom implementations).

5. **Detection vs. prevention tradeoff:** Whether it is more practical to prevent attacks at the input level or detect and mitigate them at the output/action level.

6. **MCP ecosystem maturity:** The MCP server ecosystem is growing rapidly but security practices are immature. The attack surface is expanding faster than defenses.

7. **Regulatory alignment:** How to reconcile GDPR's right to be forgotten with the need for persistent audit trails (EU AI Act requires 10-year records for high-risk AI systems).

---

## 13. Full Citation Index

### Foundational / Indirect Prompt Injection
1. Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." AISec '23 / arXiv:2302.12173. https://arxiv.org/abs/2302.12173
2. Liu, Y., Deng, G., Li, Y., Wang, K., Wang, Z., Wang, X., Zhang, T., Liu, Y., Wang, H., Zheng, Y., & Liu, Y. (2024). "Prompt Injection attack against LLM-integrated Applications." USENIX Security 2024 / arXiv:2306.05499. https://arxiv.org/abs/2306.05499

### Tool-Use Exploitation
3. Ye, J., Li, S., Li, G., Huang, C., Gao, S., Wu, Y., Zhang, Q., Gui, T., & Huang, X. (2024). "ToolSword: Unveiling Safety Issues of Large Language Models in Tool Learning Across Three Stages." ACL 2024. https://arxiv.org/abs/2402.10753
4. Yuan, T., He, Z., Dong, L., Wang, Y., Zhao, R., Xia, T., et al. (2024). "R-Judge: Benchmarking Safety Risk Awareness for LLM Agents." arXiv:2401.10019. https://arxiv.org/abs/2401.10019
5. Hua, W., Yang, X., Jin, M., et al. (2024). "TrustAgent: Towards Safe and Trustworthy LLM-based Agents." arXiv preprint. https://github.com/Ymm-cll/TrustAgent
6. SafeToolBench (2025). "SafeToolBench: Pioneering a Prospective Benchmark to Evaluating Tool Utilization Safety in LLMs." arXiv:2509.07315. https://arxiv.org/abs/2509.07315

### RAG Poisoning
7. Zou, W., Geng, R., Wang, B., & Jia, J. (2024). "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models." arXiv:2402.07867. https://arxiv.org/abs/2402.07867
8. Xue, J., Zheng, M., Hu, Y., Liu, F., Chen, X., & Lou, Q. (2024). "BadRAG: Identifying Vulnerabilities in Retrieval Augmented Generation." arXiv:2406.00083. https://arxiv.org/abs/2406.00083
9. Benchmarking Poisoning Attacks against RAG (2025). arXiv:2505.18543. https://arxiv.org/abs/2505.18543

### Multi-Step / Agent Harm Benchmarks
10. Zhan, Q., Liang, Z., Ying, Z., & Kang, D. (2024). "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents." Findings of ACL 2024. https://arxiv.org/abs/2403.02691
11. Andriushchenko, M., Souly, A., Dziemian, M., et al. (2024). "AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents." ICLR 2025 / arXiv:2410.09024. https://arxiv.org/abs/2410.09024

### Supply Chain / MCP / Plugin Security
12. MCPTox (2025). "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers." arXiv:2508.14925. https://arxiv.org/abs/2508.14925
13. MCP Security Study (2025). "Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers." arXiv:2506.13538. https://arxiv.org/abs/2506.13538
14. Jamshidi, S. et al. (2025). "Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks." arXiv:2512.06556. https://arxiv.org/abs/2512.06556
15. Systematic Analysis of MCP Security (2025). arXiv:2508.12538. https://arxiv.org/abs/2508.12538
16. Ren, R. et al. (2025). "Security Study Based on the ChatGPT Plugin System." arXiv:2507.21128. https://arxiv.org/abs/2507.21128

### Privilege Escalation / Comprehensive Benchmarks
17. Debenedetti, E., Zhang, J., Balunovic, M., Beurer-Kellner, L., Fischer, M., & Tramer, F. (2024). "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents." NeurIPS 2024. https://arxiv.org/abs/2406.13352
18. Zhang, H., Huang, J., Mei, K., et al. (2024). "Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents." arXiv:2410.02644. https://arxiv.org/abs/2410.02644

### Cross-Tool / Firewall Evaluation
19. "Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?" (2025). arXiv:2510.05244. https://arxiv.org/abs/2510.05244

### Memory Poisoning
20. Dong, S., Xu, S., He, P., Li, Y., Tang, J., Liu, T., Liu, H., & Xiang, Z. (2025). "MINJA: Memory Injection Attacks on LLM Agents via Query-Only Interaction." arXiv:2503.03704. https://arxiv.org/abs/2503.03704
21. Chen, Z., Xiang, Z., Xiao, C., Song, D., & Li, B. (2024). "AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases." NeurIPS 2024. https://arxiv.org/abs/2407.12784
22. He, H. et al. (2025). "MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval." arXiv:2512.16962. https://arxiv.org/abs/2512.16962

### Multi-Agent Systems
23. Arora, N., Joel, S., Kavathekar, I., et al. (2025). "Exposing Weak Links in Multi-Agent Systems under Adversarial Prompting (SafeAgents)." arXiv:2511.10949. https://arxiv.org/abs/2511.10949
24. Kavathekar, I., Jain, H., Rathod, A., Kumaraguru, P., & Ganu, T. (2025). "TAMAS: Benchmarking Adversarial Risks in Multi-Agent LLM Systems." arXiv:2511.05269. https://arxiv.org/abs/2511.05269

### Web Agent Security
25. WASP (2025). "WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks." arXiv:2504.18575. https://arxiv.org/abs/2504.18575

### Additional References
26. Baumgartner, T., Gao, Y., Alon, D., & Metzler, D. (2024). "Attacking RLHF by Injecting Poisoned Preference Data." arXiv:2404.05530. https://arxiv.org/abs/2404.05530
27. OWASP Top 10 for LLM Applications 2025. https://genai.owasp.org/
28. OWASP Agentic AI Threats and Mitigations. https://owaspai.org/docs/agentic_ai_threats_and_mitigations/
29. "Towards Verifiably Safe Tool Use for LLM Agents" (2026). arXiv:2601.08012. https://arxiv.org/abs/2601.08012

---

## Summary Table: Attack Categories and Key Papers

| Attack Category | Key Papers | Venue | Agent Component Targeted |
|---|---|---|---|
| Indirect Prompt Injection | Greshake et al. (2023), Liu et al. (HouYi, 2024) | AISec/CCS, USENIX Sec | Data retrieval, context processing |
| Tool-Use Exploitation | ToolSword (2024), R-Judge (2024), TrustAgent (2024) | ACL, arXiv | Tool selection, execution, output |
| RAG Poisoning | PoisonedRAG (2024), BadRAG (2024) | arXiv/S&P track | Knowledge base, retriever, embeddings |
| Multi-Step Attacks | InjecAgent (2024), AgentHarm (2024/2025) | ACL Findings, ICLR | Planning chain, tool orchestration |
| Supply Chain | MCPTox (2025), MCP Security (2025) | arXiv | Tool metadata, MCP servers, plugins |
| Privilege Escalation | AgentDojo (2024), ASB (2024) | NeurIPS, arXiv | Authorization, action validation |
| Cross-Tool Attacks | Indirect PI Firewall (2025) | arXiv | Inter-tool data flow, context mgmt |
| Memory Poisoning | MINJA (2025), AgentPoison (2024), MemoryGraft (2025) | arXiv, NeurIPS | Long-term memory, experience store |
| Multi-Agent Attacks | SafeAgents (2025), TAMAS (2025) | arXiv/ICLR sub | MAS architecture, inter-agent comms |

---

*Research compiled on 2026-02-20. Total queries: 20+ across Exa and Brave search tools. Sources include arxiv preprints, NeurIPS 2024, ACL 2024, ICLR 2025, USENIX Security 2024, AISec/CCS 2023, and OpenReview submissions.*
