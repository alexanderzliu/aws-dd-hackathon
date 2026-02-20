# Automated Red-Teaming of LLMs: Comprehensive Literature Review

**Date:** 2026-02-20
**Confidence:** High
**Tools used:** Exa (7 searches), Brave (2 searches), Firecrawl (16 page scrapes)

---

## Executive Summary

Automated red-teaming of LLMs has emerged as a critical research area since 2022, driven by the need to discover safety vulnerabilities at scale. The field has progressed from simple LLM-generated test cases (Perez et al., 2022) to sophisticated multi-agent frameworks (PAIR, TAP), evolutionary algorithms (AutoDAN, GPTFuzzer), quality-diversity optimization (Rainbow Teaming), and curiosity-driven exploration (CRT). Key themes include: (1) LLM-based attackers can jailbreak even state-of-the-art aligned models with >80-90% success rates; (2) black-box attacks requiring only API access are practical and efficient; (3) diversity of attacks matters as much as raw success rate; (4) standardized evaluation (HarmBench) enables systematic comparison; and (5) the arms race between attacks and defenses remains heavily tilted toward attackers.

---

## Table of Contents

1. [Foundational Frameworks](#1-foundational-automated-red-teaming-frameworks)
2. [LLM-Based Attack Generation (Black-Box)](#2-llm-based-attack-generation-black-box-methods)
3. [Gradient-Based and Search-Based Methods](#3-gradient-based-and-search-based-methods)
4. [Evolutionary and Fuzzing Approaches](#4-evolutionary-and-fuzzing-approaches)
5. [Diversity-Focused and Exploration Methods](#5-diversity-focused-and-exploration-methods)
6. [Multi-Turn and Persuasion-Based Attacks](#6-multi-turn-and-persuasion-based-attacks)
7. [Evaluation Frameworks and Benchmarks](#7-evaluation-frameworks-and-benchmarks)
8. [Attack Success Judges and Classifiers](#8-attack-success-judges-and-classifiers)
9. [Taxonomy of Attack Strategies](#9-taxonomy-of-attack-strategies)
10. [Key Takeaways for Building an Automated Red-Teaming Agent](#10-key-takeaways-for-building-an-automated-red-teaming-agent)

---

## 1. Foundational Automated Red-Teaming Frameworks

### 1.1 Red Teaming Language Models with Language Models (Perez et al., 2022)

- **Title:** Red Teaming Language Models with Language Models
- **Authors:** Ethan Perez, Saffron Huang, Francis Song, Trevor Cai, Roman Ring, John Aslanides, Amelia Glaese, Nat McAleese, Geoffrey Irving
- **Year:** 2022
- **Venue:** EMNLP 2022
- **URL:** https://arxiv.org/abs/2202.03286
- **Affiliation:** DeepMind

**Key Findings:**
- **Foundational paper** establishing the paradigm of using one LLM to generate test cases ("red team") for another LLM (the "target").
- Explored multiple generation methods: zero-shot generation, few-shot generation, supervised learning, and reinforcement learning (RL).
- Used a classifier trained to detect offensive content to evaluate target LM responses, uncovering **tens of thousands of offensive replies** in a 280B parameter chatbot.
- RL-based methods generated more effective (higher attack success rate) but less diverse test cases; zero-shot methods generated more diverse but less effective cases.
- Demonstrated prompt engineering to control test case generation for specific harm types: offensive group discussions, phone number leakage, private training data leakage, and multi-turn conversation harms.

**Methodology:**
- Red team LM generates test questions -> Target LM responds -> Classifier evaluates harmfulness
- Methods explored: Zero-shot, Few-shot, Stochastic Few-shot, Supervised Learning, RL (with offensive classifier as reward)
- RL reward: P(offensive | target response to generated question)

**Relevance to building a red-teaming agent:**
- Establishes the attacker-target-judge pipeline that all subsequent work builds on
- Shows the diversity-effectiveness tradeoff is a core challenge
- Demonstrates that even simple methods (zero-shot) can find harmful behaviors at scale
- RL approach maximizes attack success but collapses diversity -- a problem later addressed by Rainbow Teaming and CRT

---

## 2. LLM-Based Attack Generation (Black-Box Methods)

### 2.1 PAIR: Prompt Automatic Iterative Refinement (Chao et al., 2023)

- **Title:** Jailbreaking Black Box Large Language Models in Twenty Queries
- **Authors:** Patrick Chao, Alexander Robey, Edgar Dobriban, Hamed Hassani, George J. Pappas, Eric Wong
- **Year:** 2023 (published 2025)
- **Venue:** NeurIPS 2024 (originally arXiv Oct 2023)
- **URL:** https://arxiv.org/abs/2310.08419
- **Code:** https://github.com/patrickchao/jailbreaking-llms

**Key Findings:**
- Proposes PAIR (Prompt Automatic Iterative Refinement), a **purely black-box** method requiring only API access to the target LLM.
- Inspired by **social engineering attacks**: an attacker LLM iteratively refines jailbreak prompts based on the target's responses.
- Achieves jailbreaks in **fewer than 20 queries** -- orders of magnitude more efficient than gradient-based methods like GCG.
- Competitive success rates on GPT-3.5, GPT-4, Vicuna, and Gemini.
- Generates **semantically meaningful** jailbreaks (unlike GCG's gibberish suffixes).
- Highly transferable across models.

**Methodology:**
- Architecture: Attacker LLM + Target LLM + Judge LLM (three separate models)
- Attacker LLM receives a system prompt defining its role as a red-teamer
- Each iteration: Attacker generates candidate jailbreak -> Target responds -> Judge scores (1-10) whether jailbreak succeeded
- Attacker receives target's response and judge's score, then refines the prompt
- Terminates when judge score reaches 10 or max iterations reached
- Typically converges in 3-20 iterations

**Relevance to building a red-teaming agent:**
- **Most directly relevant paper** for building a practical automated red-teaming agent
- Demonstrates that LLM-based iterative refinement is highly effective
- The attacker-target-judge architecture is the standard pattern
- Shows that conversational context (seeing target responses) is key to effective refinement
- Very low query budget makes it practical for API-based testing

### 2.2 TAP: Tree of Attacks with Pruning (Mehrotra et al., 2023)

- **Title:** Tree of Attacks: Jailbreaking Black-Box LLMs Automatically
- **Authors:** Anay Mehrotra, Manolis Zampetakis, Paul Kassianik, Blaine Nelson, Hyrum Anderson, Yaron Singer, Amin Karbasi
- **Year:** 2023
- **Venue:** NeurIPS 2024
- **URL:** https://arxiv.org/abs/2312.02119
- **Code:** https://github.com/RICommunity/TAP

**Key Findings:**
- Extends PAIR with **tree-structured search**: instead of a single refinement chain, TAP maintains a tree of candidate attacks and explores multiple branches.
- Adds a **pruning step**: before sending prompts to the target, an evaluator LLM assesses them and prunes unlikely-to-succeed candidates, reducing query count.
- Achieves **>80% attack success rate** on GPT-4-Turbo and GPT-4o.
- Successfully jailbreaks models protected by **LlamaGuard** and other guardrails.
- Uses fewer queries than PAIR while achieving higher success rates.

**Methodology:**
- Tree search: At each level, the attacker LLM generates multiple variant prompts from each parent node
- Pruning: An evaluator (can be the attacker LLM itself) scores candidates on likelihood of jailbreaking; low-scoring branches are pruned
- Branching factor and depth are hyperparameters
- Uses three LLM roles: Attacker, Evaluator (for pruning), Target
- Judge evaluates final success

**Relevance to building a red-teaming agent:**
- Tree search is more robust than single-chain refinement -- explores diverse attack strategies simultaneously
- Pruning makes the approach query-efficient despite broader exploration
- The evaluator/pruning concept is key: don't waste target queries on low-quality attacks
- Demonstrates that combining breadth (multiple candidates) with depth (iterative refinement) outperforms either alone

---

## 3. Gradient-Based and Search-Based Methods

### 3.1 GCG: Greedy Coordinate Gradient (Zou et al., 2023)

- **Title:** Universal and Transferable Adversarial Attacks on Aligned Language Models
- **Authors:** Andy Zou, Zifan Wang, Nicholas Carlini, Milad Nasr, J. Zico Kolter, Matt Fredrikson
- **Year:** 2023
- **Venue:** arXiv (widely cited, foundational)
- **URL:** https://arxiv.org/abs/2307.15043
- **Code:** https://github.com/llm-attacks/llm-attacks

**Key Findings:**
- Proposes GCG (Greedy Coordinate Gradient), which finds **adversarial suffixes** that cause LLMs to comply with harmful queries.
- The suffix is optimized to maximize the probability that the model produces an affirmative response (e.g., starting with "Sure, here is...").
- Uses a combination of **greedy search and gradient-based** optimization over token substitutions.
- Suffixes are **universal** (work across many harmful queries) and **transferable** (work across models including ChatGPT, Bard, and Claude).
- Trained on open-source models (Vicuna-7B/13B) but transfers to closed-source APIs.
- Generated suffixes are **gibberish text** (not human-readable), making them detectable by perplexity filters.

**Methodology:**
- Objective: Maximize P(affirmative_prefix | harmful_query + adversarial_suffix)
- Search: Greedy coordinate gradient -- compute gradient of loss w.r.t. each token position in the suffix, then evaluate top-k token replacements
- Multi-prompt optimization: Optimize suffix across multiple harmful prompts simultaneously for universality
- Multi-model optimization: Optimize across multiple model checkpoints for transferability
- Requires **white-box access** (gradients) to at least one model

**Relevance to building a red-teaming agent:**
- Foundational attack method -- GCG is the baseline that many methods compare against
- **Requires white-box access** (gradient computation), limiting applicability to open-source models
- Generated suffixes are detectable by perplexity filters -- motivates AutoDAN and AdvPrompter
- Transferability finding is crucial: suffixes found on open models can attack closed APIs
- The "Sure, here is..." target is now a standard technique for steering model behavior

### 3.2 AutoDAN (Zhu et al., 2023) -- Gradient-Based Variant

- **Title:** AutoDAN: Interpretable Gradient-Based Adversarial Attacks on Large Language Models
- **Authors:** Sicheng Zhu, Ruiyi Zhang, Bang An, Gang Wu, Joe Barrow, Zichao Wang, Furong Huang, Ani Nenkova, Tong Sun
- **Year:** 2023
- **Venue:** arXiv
- **URL:** https://arxiv.org/abs/2310.15140

**Key Findings:**
- Gradient-based variant that generates **readable, interpretable** adversarial prompts (unlike GCG's gibberish).
- Optimizes tokens left-to-right with dual objectives: jailbreak success AND readability.
- Generated prompts **bypass perplexity-based filters** while maintaining high attack success rates.
- Prompts are diverse and exhibit strategies commonly seen in manual jailbreaks (role-playing, hypothetical framing).
- Better black-box transferability than GCG's unreadable suffixes.
- Can also be used to **leak system prompts** with a customized objective.

**Methodology:**
- Token-by-token generation from left to right, guided by gradients
- Dual optimization: (1) maximize jailbreak probability (2) minimize perplexity (ensure readability)
- Requires white-box access to a proxy model; attacks transfer to black-box targets
- Generates complete prompt templates, not just suffixes

### 3.3 AutoDAN (Liu et al., 2023) -- Genetic Algorithm Variant

- **Title:** AutoDAN: Generating Stealthy Jailbreak Prompts on Aligned Large Language Models
- **Authors:** Xiaogeng Liu, Nan Xu, Muhao Chen, Chaowei Xiao
- **Year:** 2023
- **Venue:** ICLR 2024
- **URL:** https://arxiv.org/abs/2310.04451
- **Code:** https://github.com/SheltonLiu-N/AutoDAN

**Key Findings:**
- Uses a **hierarchical genetic algorithm** to evolve jailbreak prompts.
- Starts with manually crafted jailbreak templates as seeds, then mutates and crossovers to create new variants.
- Generates **semantically meaningful, stealthy** prompts that bypass perplexity detection.
- Demonstrates **cross-model transferability** and **cross-sample universality**.
- Operates as a **black-box** method (no gradient access needed for the target).

**Methodology:**
- Hierarchical genetic algorithm with paragraph-level and sentence-level mutations
- Fitness function: attack success rate on target LLM
- Crossover: combine effective components from different parent prompts
- Mutation: paraphrase, substitute, or restructure sentences
- Population-based search maintains diversity

**Relevance to building a red-teaming agent:**
- Genetic algorithm approach is practical for black-box settings
- Shows that evolving from human jailbreak templates is effective
- The hierarchical mutation (paragraph + sentence level) is a useful design pattern
- Maintains semantic coherence while exploring diverse attack strategies

### 3.4 AdvPrompter (Paulus et al., 2024)

- **Title:** AdvPrompter: Fast Adaptive Adversarial Prompting for LLMs
- **Authors:** Anselm Paulus, Arman Zharmagambetov, Chuan Guo, Brandon Amos, Yuandong Tian
- **Year:** 2024
- **Venue:** ICML 2025
- **URL:** https://arxiv.org/abs/2404.16873
- **Code:** https://github.com/facebookresearch/advprompter
- **Affiliation:** Meta AI (FAIR)

**Key Findings:**
- Trains a separate **AdvPrompter LLM** to generate adversarial suffixes in a single forward pass (no iterative search at inference time).
- Generates **human-readable** adversarial suffixes that veil the input instruction without changing its meaning.
- Trained via **alternating optimization**: (1) train AdvPrompter to generate effective suffixes, (2) use generated suffixes to adversarially train the target for robustness.
- Achieves competitive results on AdvBench and HarmBench.
- **Amortized attack generation**: once trained, generates attacks in seconds (vs. minutes/hours for GCG or PAIR).

**Methodology:**
- AdvPrompter: An LLM fine-tuned to take a harmful instruction as input and output an adversarial suffix
- Training: Alternating optimization between AdvPrompter (generate suffixes) and TargetLLM (defend against suffixes)
- At inference: Single forward pass generates a suffix -- no iterative optimization
- Suffixes transfer to closed-source black-box LLMs

**Relevance to building a red-teaming agent:**
- Amortized attack generation is extremely fast -- key for red-teaming at scale
- The trained attacker model can be used as a component in a larger red-teaming system
- Dual-use: same method can train both better attacks AND better defenses

### 3.5 Simple Adaptive Attacks (Andriushchenko et al., 2024)

- **Title:** Jailbreaking Leading Safety-Aligned LLMs with Simple Adaptive Attacks
- **Authors:** Maksym Andriushchenko, Francesco Croce, Nicolas Flammarion
- **Year:** 2024
- **Venue:** ICLR 2025
- **URL:** https://arxiv.org/abs/2404.02151
- **Code:** https://github.com/tml-epfl/llm-adaptive-attacks

**Key Findings:**
- Demonstrates that **simple random search** on adversarial suffixes (maximizing logprob of "Sure" token) achieves **100% attack success rate** across many models.
- Achieves 100% ASR on: Vicuna-13B, Mistral-7B, Phi-3-Mini, Nemotron-4-340B, Llama-2-Chat (7B/13B/70B), Llama-3-Instruct-8B, Gemma-7B, GPT-3.5, GPT-4o.
- For models without logprob access (Claude), uses **transfer attacks** or **prefilling attacks** with 100% success rate.
- Core insight: **Adaptivity is crucial** -- different models require different prompt templates and attack strategies.
- Won 1st place in SaTML'24 Trojan Detection Competition using the same random search approach.

**Methodology:**
- Design an adversarial prompt template (sometimes model-specific)
- Apply random search on a suffix to maximize target logprob (e.g., P("Sure"))
- Use multiple restarts for robustness
- For Claude: prefilling attack (inject tokens into the assistant turn prefix)
- For fully black-box: transfer attacks from open-source proxy models

**Relevance to building a red-teaming agent:**
- Shows that sophisticated methods are not always necessary -- simple adaptive approaches can be devastatingly effective
- The importance of **model-specific adaptation** is a key lesson
- Logprob access (available via many APIs) enables powerful optimization
- Template adaptation per target model should be a core feature of any red-teaming system

---

## 4. Evolutionary and Fuzzing Approaches

### 4.1 GPTFUZZER (Yu et al., 2023)

- **Title:** GPTFUZZER: Red Teaming Large Language Models with Auto-Generated Jailbreak Prompts
- **Authors:** Jiahao Yu, Xingwei Lin, Zheng Yu, Xinyu Xing
- **Year:** 2023
- **Venue:** arXiv (2023)
- **URL:** https://arxiv.org/abs/2309.10253

**Key Findings:**
- Inspired by **AFL (American Fuzzy Lop)** software fuzzing framework -- applies fuzzing methodology to LLM jailbreaking.
- Starts with **human-written jailbreak templates as seeds**, then mutates them to generate new templates.
- Three key components: (1) seed selection strategy for balancing efficiency and variability, (2) mutation operators for creating semantically equivalent sentences, (3) judgment model to assess jailbreak success.
- Achieves **>90% attack success rate** on ChatGPT and Llama-2 models, even with suboptimal initial seeds.
- Surpasses human-crafted templates in effectiveness.

**Methodology:**
- Seed corpus: Collection of human-written jailbreak templates
- Seed selection: Energy-based scheduling (similar to AFL) balancing exploitation of successful seeds and exploration of new ones
- Mutation operators: (1) Crossover between templates (2) Expand -- add detail (3) Shorten (4) Rephrase (5) Generate similar
- Judgment model: Fine-tuned RoBERTa classifier to detect whether a response constitutes a successful jailbreak
- Iterative fuzzing loop: Select seed -> Mutate -> Test against target -> Update seed corpus

**Relevance to building a red-teaming agent:**
- Software fuzzing paradigm maps well to LLM red-teaming
- Seed corpus + mutation is a practical and effective approach
- The mutation operators (crossover, expand, shorten, rephrase) are directly applicable
- Energy-based seed selection ensures both efficiency and coverage
- Judgment model (classifier) is more efficient than LLM-as-judge for high-throughput testing

---

## 5. Diversity-Focused and Exploration Methods

### 5.1 Rainbow Teaming (Samvelyan et al., 2024)

- **Title:** Rainbow Teaming: Open-Ended Generation of Diverse Adversarial Prompts
- **Authors:** Mikayel Samvelyan, Sharath Chandra Raparthy, Andrei Lupu, Eric Hambro, Aram H. Markosyan, Manish Bhatt, Yuning Mao, Minqi Jiang, Jack Parker-Holder, Jakob Foerster, Tim Rocktaschel, Roberta Raileanu
- **Year:** 2024
- **Venue:** NeurIPS 2024
- **URL:** https://arxiv.org/abs/2402.16822
- **Affiliation:** Meta AI (FAIR)

**Key Findings:**
- Casts adversarial prompt generation as a **quality-diversity (QD) optimization** problem.
- Uses **MAP-Elites** algorithm adapted for LLM attacks: maintains an archive of attacks indexed by behavior descriptors (e.g., attack category, topic, style).
- Generates prompts that are both **effective AND diverse** -- solves the diversity-effectiveness tradeoff.
- Attack success rate **>90%** across Llama 2 and Llama 3 models.
- Generated prompts are **highly transferable** across models.
- Fine-tuning on Rainbow Teaming-generated data **improves model safety** without sacrificing helpfulness.
- Versatile: applied to safety, question answering, and cybersecurity domains.

**Methodology:**
- Quality-Diversity framework: MAP-Elites maintains a grid of "niches" (behavior descriptors)
- Each niche contains the best-performing attack for that combination of descriptors
- Descriptors: risk category, attack style, topic domain
- Mutation: LLM rewrites/evolves attacks while targeting specific niches
- Quality: Attack success rate measured by a safety classifier
- Open-ended: can discover entirely new attack categories not specified a priori

**Relevance to building a red-teaming agent:**
- **Critical paper** for comprehensive red-teaming -- addresses the diversity problem head-on
- MAP-Elites framework ensures coverage across attack categories, styles, and topics
- The quality-diversity approach is ideal for building comprehensive test suites
- Generated attacks can be used for both evaluation AND safety fine-tuning (dual-use)
- Open-ended exploration can discover novel attack vectors

### 5.2 Curiosity-Driven Red-Teaming (Hong et al., 2024)

- **Title:** Curiosity-driven Red-teaming for Large Language Models
- **Authors:** Zhang-Wei Hong, Idan Shenfeld, Tsun-Hsuan Wang, Yung-Sung Chuang, Aldo Pareja, James Glass, Akash Srivastava, Pulkit Agrawal
- **Year:** 2024
- **Venue:** ICLR 2024
- **URL:** https://arxiv.org/abs/2402.19464
- **Code:** https://github.com/Improbable-AI/curiosity_redteam
- **Affiliation:** MIT

**Key Findings:**
- Draws on **curiosity-driven exploration** from RL to increase the diversity and coverage of red-teaming test cases.
- Standard RL red-teaming maximizes attack success but collapses to a small set of effective prompts; CRT adds **novelty bonus** to encourage exploration.
- Uses Random Network Distillation (RND) as the curiosity signal -- rewards generating test cases that are different from previously seen ones.
- Achieves **greater coverage** of the attack surface while maintaining or increasing effectiveness.
- Successfully provokes toxic responses from LLaMA-2 (which was heavily fine-tuned to avoid toxic outputs).

**Methodology:**
- RL-based red-teaming with curiosity bonus
- Reward = attack_success_score + beta * novelty_bonus
- Novelty measured via Random Network Distillation (RND): a fixed random network and a trained predictor network; prediction error serves as novelty signal
- Higher novelty = more reward for exploring unseen regions of prompt space
- Balances exploitation (effective attacks) with exploration (diverse attacks)

**Relevance to building a red-teaming agent:**
- Directly addresses the diversity collapse problem in RL-based red-teaming
- Curiosity bonus is a principled way to encourage coverage
- Could be combined with PAIR/TAP-style iterative refinement
- The RND novelty signal is relatively simple to implement

---

## 6. Multi-Turn and Persuasion-Based Attacks

### 6.1 RED-EVAL / Chain of Utterances (Bhardwaj & Poria, 2023)

- **Title:** Red-Teaming Large Language Models using Chain of Utterances for Safety-Alignment
- **Authors:** Rishabh Bhardwaj, Soujanya Poria
- **Year:** 2023
- **Venue:** arXiv
- **URL:** https://arxiv.org/abs/2308.09662

**Key Findings:**
- Proposes **Chain of Utterances (CoU)** prompting for multi-turn jailbreaking.
- Jailbreaks GPT-4 on **65%** and ChatGPT on **73%** of harmful queries.
- Across 8 open-source LLMs, generates harmful responses in **>86%** of red-teaming attempts.
- Introduces **RED-EVAL** benchmark for safety evaluation.
- Also proposes **RED-INSTRUCT** for safety alignment using collected harmful/safe conversation pairs (1.9K harmful questions, 9.5K safe + 7.3K harmful conversations).
- Fine-tuned model **STARLING** shows improved safety alignment.

**Methodology:**
- Chain of Utterances (CoU): Multi-turn dialogue where each turn builds on previous context to gradually steer the conversation toward harmful territory
- Similar to how social engineers gradually escalate requests
- Collects HARMFULQA dataset via CoU prompting of ChatGPT
- SAFE-ALIGN: Fine-tune model to maximize helpful response likelihood and penalize harmful responses

**Relevance to building a red-teaming agent:**
- Multi-turn attacks are more realistic and harder to defend against
- CoU demonstrates that gradually escalating requests is effective
- The dataset collection methodology (using attacks to generate training data for defense) is a key pattern

### 6.2 Persuasive Adversarial Prompts / PAP (Zeng et al., 2024)

- **Title:** How Johnny Can Persuade LLMs to Jailbreak Them: Rethinking Persuasion to Challenge AI Safety by Humanizing LLMs
- **Authors:** Yi Zeng, Hongpeng Lin, Jingwen Zhang, Diyi Yang, Ruoxi Jia, Weiyan Shi
- **Year:** 2024
- **Venue:** arXiv (ACL 2024)
- **URL:** https://arxiv.org/abs/2401.06373

**Key Findings:**
- Treats LLMs as **human-like communicators** and applies **social science persuasion techniques** to jailbreak them.
- Proposes a **persuasion taxonomy** derived from decades of social science research (40 persuasion techniques).
- Automatically generates **Persuasive Adversarial Prompts (PAP)** using the taxonomy.
- Achieves **>92% attack success rate** on Llama 2-7b Chat, GPT-3.5, and GPT-4 in 10 trials.
- **Surpasses algorithm-focused attacks** -- persuasion is more effective than gradient-based methods.
- Existing defenses have **significant gaps** against persuasion-based attacks.

**Methodology:**
- Persuasion taxonomy: 40 techniques including authority appeal, emotional manipulation, logical framing, social proof, reciprocity, etc.
- PAP generation: LLM generates adversarial prompts by applying specific persuasion techniques to harmful queries
- Each technique creates a different "angle of attack"
- Evaluated across multiple risk categories (hate speech, violence, fraud, etc.)

**Relevance to building a red-teaming agent:**
- The persuasion taxonomy provides a **structured framework** for generating diverse attacks
- Social engineering techniques transfer from human manipulation to LLM manipulation
- 40 persuasion techniques provide 40 independent attack "strategies" to try
- Much harder to defend against than algorithmic attacks because the prompts are natural language
- Directly applicable to multi-turn conversational attacks

---

## 7. Evaluation Frameworks and Benchmarks

### 7.1 HarmBench (Mazeika et al., 2024)

- **Title:** HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal
- **Authors:** Mantas Mazeika, Long Phan, Xuwang Yin, Andy Zou, Zifan Wang, Norman Mu, Elham Sakhaee, Nathaniel Li, Steven Basart, Bo Li, David Forsyth, Dan Hendrycks
- **Year:** 2024
- **Venue:** ICML 2024
- **URL:** https://arxiv.org/abs/2402.04249
- **Code:** https://github.com/centerforaisafety/HarmBench
- **Website:** https://www.harmbench.org/

**Key Findings:**
- **Standardized evaluation framework** for automated red teaming -- the current gold standard.
- Compares **18 red teaming methods** against **33 target LLMs and defenses** in a large-scale study.
- Identifies desirable properties for red-teaming evaluations: (1) diverse behavior coverage, (2) standardized success criteria, (3) computational efficiency, (4) open-source reproducibility.
- Uses a fine-tuned **Llama-2-13b classifier** as the judge for attack success (trained to be more reliable than simple string matching).
- Also introduces an adversarial training defense method that significantly enhances LLM robustness.
- Behavior categories: standard harmful behaviors, contextual behaviors (copyright, misinformation), multimodal behaviors.

**Methodology:**
- Curated set of harmful behaviors spanning multiple risk categories
- Standardized API for running attack methods against target models
- Attack Success Rate (ASR) as primary metric, computed via fine-tuned classifier judge
- Supports both text-only and multimodal attacks
- Comprehensive leaderboard-style comparison

**Relevance to building a red-teaming agent:**
- **Must-use benchmark** for evaluating any automated red-teaming system
- The fine-tuned classifier judge is more reliable than GPT-4-as-judge for standardized comparison
- Provides a structured set of harmful behaviors for testing
- Enables fair comparison between different attack methods

---

## 8. Attack Success Judges and Classifiers

### 8.1 WildGuard (Han et al., 2024)

- **Title:** WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of LLMs
- **Authors:** Seungju Han, Kavel Rao, Allyson Ettinger, Liwei Jiang, Bill Yuchen Lin, Nathan Lambert, Yejin Choi, Nouha Dziri
- **Year:** 2024
- **Venue:** NeurIPS 2024
- **URL:** https://arxiv.org/abs/2406.18495

**Key Findings:**
- Open-source moderation tool for: (1) identifying malicious intent in user prompts, (2) detecting safety risks in model responses, (3) determining model refusal rate.
- Covers **13 risk categories**.
- Trained on **WildGuardMix** -- 92K labeled examples covering both vanilla prompts and adversarial jailbreaks.
- **Matches or exceeds GPT-4** on prompt harmfulness identification (up to 3.9% improvement).
- Up to **26.4% improvement** on refusal detection vs. existing open-source tools.
- As a safety moderator, reduces jailbreak success from **79.8% to 2.4%**.

**Relevance to building a red-teaming agent:**
- Can serve as the **judge component** in an attacker-target-judge pipeline
- More efficient than GPT-4-as-judge for high-throughput evaluation
- Three-in-one: classifies prompt harm, response harm, and refusal
- Open-source and lightweight -- practical for integration

### 8.2 Common Judging Approaches

Multiple papers use these judging strategies:

| Method | Description | Pros | Cons |
|--------|-------------|------|------|
| **String matching** | Check if response starts with "I cannot" / "I'm sorry" | Fast, simple | High false positive/negative rate |
| **GPT-4-as-judge** | Prompt GPT-4 to rate attack success (1-10) | High accuracy | Expensive, rate-limited, non-reproducible |
| **Fine-tuned classifier** | Trained on labeled jailbreak data (HarmBench, WildGuard) | Reproducible, efficient | Requires training data, may miss novel attacks |
| **Llama Guard / Llama Guard 2** | Meta's safety classifier | Open-source, decent accuracy | Weaker on adversarial jailbreaks |
| **Toxicity classifiers** | Perspective API, toxicity models | Fast, well-calibrated | Only captures toxicity, not other harms |
| **Semantic similarity** | Compare response to "ideal" harmful response | Captures content quality | Requires reference harmful responses |

---

## 9. Taxonomy of Attack Strategies

Based on the literature, attacks can be categorized along multiple dimensions:

### By Access Level
| Level | Methods | Requirements |
|-------|---------|--------------|
| **White-box** | GCG, AutoDAN (gradient) | Model weights, gradients |
| **Gray-box** | Adaptive Attacks | Logprobs from API |
| **Black-box** | PAIR, TAP, GPTFuzzer, Rainbow Teaming | Text-only API access |

### By Optimization Strategy
| Strategy | Methods | Mechanism |
|----------|---------|-----------|
| **Gradient-based** | GCG, AutoDAN (Zhu) | Optimize token-level via gradients |
| **Search-based** | Random Search, Adaptive Attacks | Random/greedy search over token space |
| **LLM-based refinement** | PAIR, TAP | Attacker LLM iteratively refines prompts |
| **Evolutionary** | AutoDAN (Liu), GPTFuzzer | Genetic algorithms, mutation, crossover |
| **Quality-Diversity** | Rainbow Teaming | MAP-Elites, open-ended search |
| **RL-based** | CRT, Perez et al. | Reinforcement learning with reward |
| **Trained generator** | AdvPrompter | Amortized generation via fine-tuned LLM |

### By Attack Type
| Type | Description | Examples |
|------|-------------|----------|
| **Adversarial suffix** | Append gibberish/readable suffix to harmful query | GCG, AutoDAN, AdvPrompter |
| **Jailbreak template** | Wrap harmful query in a role-play/scenario template | GPTFuzzer, DAN prompts |
| **Iterative refinement** | Refine attack prompt based on target feedback | PAIR, TAP |
| **Persuasion** | Apply social engineering / persuasion techniques | PAP |
| **Multi-turn** | Gradually escalate across conversation turns | CoU, multi-turn PAIR |
| **Encoding/obfuscation** | Base64, ROT13, word substitution, etc. | Various manual techniques |

### By Diversity Mechanism
| Mechanism | Methods | How It Works |
|-----------|---------|--------------|
| **Curiosity bonus** | CRT | Novelty reward via RND |
| **Quality-Diversity** | Rainbow Teaming | MAP-Elites archive across behavior descriptors |
| **Population diversity** | AutoDAN (Liu), GPTFuzzer | Genetic algorithm maintains diverse population |
| **Taxonomy-guided** | PAP | 40 persuasion techniques as structured diversity |
| **Tree search** | TAP | Multiple branches explore different strategies |

---

## 10. Key Takeaways for Building an Automated Red-Teaming Agent

### Architecture
1. **Attacker-Target-Judge pipeline** (Perez et al., PAIR) is the standard architecture.
2. Use an **LLM as the attacker** -- it generates more natural, diverse, and effective attacks than algorithmic methods.
3. **Iterative refinement** (PAIR) with **tree search** (TAP) gives the best single-attack success rate.
4. For **comprehensive coverage**, use quality-diversity methods (Rainbow Teaming) or taxonomy-guided generation (PAP).

### Attack Strategy
5. **Start with a diverse seed corpus** of known attack templates (GPTFuzzer approach).
6. **Mutate and evolve** seeds through paraphrase, expansion, crossover (GPTFuzzer, AutoDAN).
7. **Use multiple attack strategies** in parallel: role-playing, persuasion, encoding, scenario framing, etc.
8. **Adapt to the target model** -- different models have different vulnerabilities (Adaptive Attacks paper).
9. **Multi-turn attacks** are more realistic and harder to defend against than single-turn.
10. **Persuasion techniques** (PAP) are highly effective and generate natural-language attacks.

### Evaluation
11. Use **multiple judges**: string matching for quick screening, fine-tuned classifier (HarmBench/WildGuard) for accuracy, GPT-4-as-judge for nuanced assessment.
12. **Attack Success Rate (ASR)** is the primary metric, but also measure **diversity** and **coverage** across harm categories.
13. Evaluate on **standardized benchmarks** (HarmBench, AdvBench) for comparability.
14. Consider **transferability testing** -- do attacks found on one model work on others?

### Scaling
15. **Amortized attack generation** (AdvPrompter) enables testing at scale without per-attack optimization.
16. **Fuzzing loops** (GPTFuzzer) can run continuously, building an ever-expanding corpus of effective attacks.
17. **Quality-Diversity archives** (Rainbow Teaming) ensure comprehensive coverage even at scale.
18. Use **pruning** (TAP) to avoid wasting target API calls on low-quality attacks.

### Diversity
19. **Diversity is as important as effectiveness** -- a single high-ASR attack that covers one category is less useful than moderate-ASR attacks across many categories.
20. Use **structured diversity**: taxonomy of attack categories, persuasion techniques, risk categories, and attack styles.
21. **Curiosity-driven exploration** (CRT) prevents mode collapse in RL-based methods.

---

## Full Citation List

### Foundational
1. Perez, E., Huang, S., Song, F., Cai, T., Ring, R., Aslanides, J., Glaese, A., McAleese, N., & Irving, G. (2022). Red Teaming Language Models with Language Models. *EMNLP 2022*. https://arxiv.org/abs/2202.03286

### LLM-Based Black-Box Attacks
2. Chao, P., Robey, A., Dobriban, E., Hassani, H., Pappas, G. J., & Wong, E. (2023). Jailbreaking Black Box Large Language Models in Twenty Queries. *NeurIPS 2024*. https://arxiv.org/abs/2310.08419
3. Mehrotra, A., Zampetakis, M., Kassianik, P., Nelson, B., Anderson, H., Singer, Y., & Karbasi, A. (2023). Tree of Attacks: Jailbreaking Black-Box LLMs Automatically. *NeurIPS 2024*. https://arxiv.org/abs/2312.02119

### Gradient-Based and Search-Based
4. Zou, A., Wang, Z., Carlini, N., Nasr, M., Kolter, J. Z., & Fredrikson, M. (2023). Universal and Transferable Adversarial Attacks on Aligned Language Models. *arXiv*. https://arxiv.org/abs/2307.15043
5. Zhu, S., Zhang, R., An, B., Wu, G., Barrow, J., Wang, Z., Huang, F., Nenkova, A., & Sun, T. (2023). AutoDAN: Interpretable Gradient-Based Adversarial Attacks on Large Language Models. *arXiv*. https://arxiv.org/abs/2310.15140
6. Liu, X., Xu, N., Chen, M., & Xiao, C. (2023). AutoDAN: Generating Stealthy Jailbreak Prompts on Aligned Large Language Models. *ICLR 2024*. https://arxiv.org/abs/2310.04451
7. Paulus, A., Zharmagambetov, A., Guo, C., Amos, B., & Tian, Y. (2024). AdvPrompter: Fast Adaptive Adversarial Prompting for LLMs. *ICML 2025*. https://arxiv.org/abs/2404.16873
8. Andriushchenko, M., Croce, F., & Flammarion, N. (2024). Jailbreaking Leading Safety-Aligned LLMs with Simple Adaptive Attacks. *ICLR 2025*. https://arxiv.org/abs/2404.02151

### Evolutionary and Fuzzing
9. Yu, J., Lin, X., Yu, Z., & Xing, X. (2023). GPTFUZZER: Red Teaming Large Language Models with Auto-Generated Jailbreak Prompts. *arXiv*. https://arxiv.org/abs/2309.10253

### Diversity-Focused
10. Samvelyan, M., Raparthy, S. C., Lupu, A., Hambro, E., Markosyan, A. H., Bhatt, M., Mao, Y., Jiang, M., Parker-Holder, J., Foerster, J., Rocktaschel, T., & Raileanu, R. (2024). Rainbow Teaming: Open-Ended Generation of Diverse Adversarial Prompts. *NeurIPS 2024*. https://arxiv.org/abs/2402.16822
11. Hong, Z.-W., Shenfeld, I., Wang, T.-H., Chuang, Y.-S., Pareja, A., Glass, J., Srivastava, A., & Agrawal, P. (2024). Curiosity-driven Red-teaming for Large Language Models. *ICLR 2024*. https://arxiv.org/abs/2402.19464

### Multi-Turn and Persuasion
12. Bhardwaj, R. & Poria, S. (2023). Red-Teaming Large Language Models using Chain of Utterances for Safety-Alignment. *arXiv*. https://arxiv.org/abs/2308.09662
13. Zeng, Y., Lin, H., Zhang, J., Yang, D., Jia, R., & Shi, W. (2024). How Johnny Can Persuade LLMs to Jailbreak Them: Rethinking Persuasion to Challenge AI Safety by Humanizing LLMs. *ACL 2024*. https://arxiv.org/abs/2401.06373

### Evaluation and Benchmarks
14. Mazeika, M., Phan, L., Yin, X., Zou, A., Wang, Z., Mu, N., Sakhaee, E., Li, N., Basart, S., Li, B., Forsyth, D., & Hendrycks, D. (2024). HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal. *ICML 2024*. https://arxiv.org/abs/2402.04249
15. Han, S., Rao, K., Ettinger, A., Jiang, L., Lin, B. Y., Lambert, N., Choi, Y., & Dziri, N. (2024). WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of LLMs. *NeurIPS 2024*. https://arxiv.org/abs/2406.18495

---

## Open Questions and Future Directions

1. **Multi-turn attack research is underexplored** -- most papers focus on single-turn jailbreaks, but real attacks often unfold over multiple turns.
2. **Defense-aware attacks** -- how do attacks need to adapt when targets use guardrails like Llama Guard, system-level defenses, or input/output filters?
3. **Agentic red-teaming** -- combining tool use, multi-step reasoning, and iterative attack refinement in a single agent.
4. **Cross-modality attacks** -- extending text attacks to multimodal models (vision-language models) is an emerging area.
5. **Evaluation beyond ASR** -- measuring the quality, realism, and severity of successful attacks, not just binary success/failure.
6. **Attacks on reasoning models** (o1, o3, Claude with extended thinking) -- these models may have different vulnerability profiles.
7. **Dynamic/adaptive defenses** -- models that detect and adapt to ongoing attack attempts in real-time.

---

## Recommended Reading Order for Practitioners

1. **Start here:** Perez et al. (2022) -- establishes the fundamental paradigm
2. **Core attack methods:** PAIR (Chao et al.) -> TAP (Mehrotra et al.) -> GCG (Zou et al.)
3. **Diversity:** Rainbow Teaming (Samvelyan et al.) -> CRT (Hong et al.)
4. **Evaluation:** HarmBench (Mazeika et al.) -> WildGuard (Han et al.)
5. **Advanced attacks:** AutoDAN (Liu et al.) -> GPTFuzzer (Yu et al.) -> AdvPrompter (Paulus et al.)
6. **Social engineering angle:** PAP (Zeng et al.) -> CoU (Bhardwaj & Poria)
7. **Practical considerations:** Adaptive Attacks (Andriushchenko et al.)
