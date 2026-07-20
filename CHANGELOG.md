# Changelog

## [0.0.8] - 2026-07-20

### Added
- 3 new skills: malware_drop, encryption_timeline, source_ip_extraction
  - malware_drop: install.exe, ProgramData, C:\ProgramData\install, binary size
  - encryption_timeline: mass file mods, .td1738, td1738-readme, encryption window
  - source_ip_extraction: 172.16.2.x IPs, NEBO\ users, source-to-activity mapping
- Explicit IOC injection in retrieval: 16 IOC keywords searched individually
  (5 hits each), guaranteed in final result set regardless of score ranking
- IOC-priority hit ordering: IOC hits placed first, then score-ranked hits

### Changed
- LOGON_ANALYSIS skill: expanded keywords (RDP, type 10, NEBO, S-1-5-7, NTLM V1,
  ANONYMOUS, adm_pavel, kirill), 7 follow-up questions with IP correlation
- MFT_FILESYSTEM skill: priority 2->1, added td1738-readme, C:\ProgramData\install,
  file modification/rename keywords, ransom note follow-up
- _retrieve_with_skill: keyword search k doubled (k*2), event_id filter no longer
  discards keyword hits (merges instead)
- _retrieve_assessment: per-skill guaranteed representation (5 hits minimum),
  IOC hits bypass score cutoff, k*4 cap (was k*3)
- IOC coverage on SRV.nebo.ru: 12/12 gap IOCs now in hits (was 4/12)
  - 172.16.2.20/21/22: all three source IPs found
  - kirill: found in 4624/4672 events
  - install.exe: found in UserAssist/MFT events
  - td1738: found in registry events
  - All previously missing IOCs now surface in LLM report

### Added
- Plaso knowledge base (src/agents/plaso_knowledge.py):
  - 58 parsers parsed from `log2timeline --parsers list`
  - DFIR-specific metadata for 14 key parsers (use cases, artifact sources, scenarios)
  - 7 parser presets: windows_full, windows_triage, ransomware, lateral_movement,
    persistence, user_activity, minimal
  - format_for_llm() injects parser knowledge into agent prompt
  - find_parsers_for_artifact(), parsers_for_scenario(), get_preset()
- Plaso documentation scraped from readthedocs.io (8 pages in docs/plaso_docs/)
- docs/plaso_parsers.json: structured parser catalog
- PLASO_KNOWLEDGE skill: retrieves events by parser type, asks follow-up
  questions about which parser produced each artifact
- Time-slicing for RAG (two-phase retrieval):
  - Phase 1: broad retrieval to detect incident time window
  - Phase 2: time-sliced retrieval focused on incident window (+/- 30 min)
  - _detect_incident_window(): clusters suspicious events within 2h windows
  - time_range/time_after/time_before filters in TurboVec
- 10 new tests: test_plaso_kb.py (7) + test_agent.py (3 for time/plaso)

### Changed
- dfir_agent.py: two-phase retrieval with time-window detection
  - _retrieve_with_skill() accepts time_window parameter
  - _retrieve_incident/_retrieve_assessment: phase 1 -> detect window -> phase 2
  - Plaso knowledge context injected into LLM prompt
- skills.py: PLASO_KNOWLEDGE skill added to both INCIDENT and ASSESSMENT skills
- turbovec.py: time_after/time_before filters added to _matches()

### Added
- Agent skills system (src/agents/skills.py): 11 domain-specific skills
  - service_abuse, lateral_movement, ransomware, impacket_smbexec, recon
  - logon_analysis, amcache_execution, mft_filesystem
  - persistence, user_activity, network_indicators (assessment-only)
- Hybrid retrieval: semantic (TF-IDF) + keyword (substring match) per skill
- TurboVec.keyword_search(): case-insensitive keyword matching with filters
- Enhanced agent prompts: IOC extraction, Impacket vs PsExec distinction,
  recon command sequencing, WHO/WHEN/HOW establishment
- AgentResult.skills_used: tracks which skills contributed hits
- Follow-up questions passed to LLM for structured analysis
- docs/skills.md: skill documentation
- Assessment report with skills on SRV.nebo.ru found:
  - Full BTOBTO command sequence (whoami -> tasklist -> ping ya.ru -> dir -> ipconfig -> netstat)
  - Anonymous NTLM V1 logon (not in reference report!)
  - 11 MITRE ATT&CK TTPs (vs 4 without skills)
  - Detailed IOCs: service names, paths, users, network indicators, command patterns
  - RISK LEVEL: CRITICAL

### Changed
- dfir_agent.py: rewritten for skill-based hybrid retrieval
  - _retrieve_with_skill(): semantic + keyword + event_id per skill
  - _retrieve_incident/_retrieve_assessment: iterate over skill collections
  - Enhanced prompts with follow-up questions and skills summary
- tests/test_agent.py: 10 tests (skills, keyword search, agent modes)
- turbovec.py: added keyword_search method

### Added
- Two agent modes: incident investigation + compromise assessment
  - incident: analyst provides description, agent does targeted retrieval
  - assess: autonomous exploration, no description needed, broader query set
- Assessment mode finds additional anomalies vs incident mode:
  - "BTOBTO" service running ipconfig/netstat reconnaissance via batch
  - Output redirection to \\127.0.0.1\C$\__output (PsExec pattern)
  - WinRM/RDP attack surface identification
  - RISK LEVEL: CRITICAL with justification
- CLI subcommands: `incident --incident "..."` and `assess`
- Agent tests: test_incident_mode, test_assessment_mode, test_run_dispatch,
  test_assessment_retrieval_broader (MockLLM, no external API needed)
- Separate report files: report_incident.md, report_assessment.md
- docs/agent_design.md: documented both modes

### Changed
- dfir_agent.py: split into run_incident/run_assess, separate prompts,
  broader EVTX/REG/FILE query sets for assessment mode
- cli.py: subcommand architecture (incident/assess)

### Added
- Ollama Cloud LLM integration (glm-5.2 via https://ollama.com/v1)
- OllamaLLM: dual-mode (local /api/chat + cloud /v1/chat/completions)
- TfidfEmbedder: lightweight TF-IDF with char n-grams, numpy-only, persistable
- Agent CLI: python -m src.agents.cli run --case --incident
- DFIR agent: multi-query retrieval strategy (broad + EVTX + REG filtered)
- Real DFIR report generated for SRV.nebo.ru ransomware case:
  - Found suspicious services "McBz" (HYlugqMY.exe) and "Sauh" (pnLXsIao.exe)
  - Found PsExec usage (3x between 08:03-08:04 UTC on 2021-04-19)
  - Identified user "ivan" activity during incident window
  - Mapped to MITRE ATT&CK: T1543.003, T1021.002, T1569.002, T1078
  - Generated IOCs, hypotheses, recommendations, open questions
  - All findings cited with chunk.id references
- Embedder persistence: TF-IDF vocab/IDF saved as embedder.npz alongside index

### Changed
- .env.example: Ollama Cloud config (host, api key, model glm-5.2)
- Embedder factory: separate EMBEDDER_BACKEND from LLM_BACKEND
- Indexer: pre-fits TF-IDF on corpus, saves embedder state
- turboVEC rebuilt on real case with TF-IDF (333,945 vectors, dim=512)

### Added
- Real case pipeline validation on SRV.nebo.ru ransomware triage (test-case/)
  - plaso log2timeline: 178 sources, 342,339 events (2m20s)
  - psort json_line: 342,933 events -> 458 MB JSONL (3m19s)
  - normalizer: 333,945 unique events (8,394 duplicates removed)
  - turboVEC: 333,945 vectors, dim=256, indexed in 24s, 565 MB on disk
  - RAG queries validated: login/process/service/encryption retrieval works
- data/triage/srv-nebo-encryption/case.json: real case metadata

### Changed
- normalizer: rewritten for plaso 20260512 json_line schema (timestamp as int
  microseconds, date_time object, data_type classification, event_id extraction
  from message prefix "[NNNN / 0xNNNN]")
- run_plaso.sh / runner / .env.example: parser preset win7 -> winevtx,winreg,
  prefetch,filestat; psort format jsonl -> json_line
- tests/test_normalizer: updated for new plaso schema (5 tests, all passing)

### Fixed
- Dockerfile.plaso: PPA gift/stable for plaso-tools
- runner.py: import os moved to top-level

### Added
- src/rag/turbovec.py: TurboVec vector store (numpy + persistence, metadata filters)
- src/rag/chunker.py: event_to_chunk, chunk_events_file, write_chunks (1 event = 1 chunk)
- src/rag/embedder.py: DummyEmbedder, OllamaEmbedder, OpenAIEmbedder + factory
- src/rag/indexer.py: build_index_from_events, load_index, query_store
- src/pipeline/normalizer.py: plaso JSONL -> normalized events.jsonl with dedup
- src/pipeline/runner.py: full pipeline orchestrator (plaso Docker -> normalize -> index)
- src/agents/llm.py: OllamaLLM, OpenAILLM + factory
- src/agents/dfir_agent.py: DFIRAgent with RAG retrieval + structured report prompt
- tests: test_turbovec (4), test_chunker (4), test_normalizer (3), test_embedder (3),
  test_e2e_pipeline (1) - 17 tests total, all passing

### Fixed
- src/pipeline/runner.py: moved `import os` to top-level (was inside function)
- tests/test_placeholder.py: aligned with src/ layout

## [0.0.1] - 2026-07-20

### Added
- Инициализация проекта и git-репозитория
- Базовая структура: src/pipeline, src/rag, src/agents, src/wiki
- Документация: architecture, pipeline, rag_design, agent_design, llm_wiki, data_flow, decisions, glossary
- Wiki-структура: ttp, ioc, reports, playbooks
- Docker-обвязка для plaso (Dockerfile.plaso + run_plaso.sh)
- Статья от автора с описанием идеи и текущего прогресса (article/author_article.md)
- pyproject.toml, .env.example, .gitignore