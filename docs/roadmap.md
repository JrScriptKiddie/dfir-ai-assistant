# Roadmap / TO-DO

## Context Budget Formula (implemented)

Проблема: при большом количестве логов RAG может перегрузить контекст LLM,
модель "забуксует" - качество анализа упадёт.

Решение: context budget calculator (src/agents/context_budget.py).

Формула:
```
available_tokens = context_window * input_ratio - fixed_overhead
max_hits = available_tokens // per_hit_tokens
recommended_hits = min(max_hits, window_adjusted_cap)

window_adjusted_cap = base_cap * sqrt(window_hours / reference_hours)
```

Параметры:
- context_window: размер контекста модели (glm-5.2 = 128K, qwen2.5 = 32K)
- input_ratio: доля контекста для входа (0.75 = 75%, 25% для ответа)
- fixed_overhead: ~2700 tokens (system prompt + skills + plaso KB + follow-ups)
- per_hit_tokens: ~55 tokens (chunk_id + score + event text)
- window_hours: ширина окна инцидента (sqrt scaling - удвоение окна не удваивает hits)
- min_hits: 30 (минимум для полезного анализа)

Гарантии:
- total_input_tokens <= context_window * input_ratio (no overflow)
- response_tokens >= context_window * (1 - input_ratio)
- hits >= min_hits (полезный минимум)

На кейсе SRV.nebo.ru (333K events, 26 min window, glm-5.2):
- recommended_hits: ~100 (текущее k*4=100 - в рамках бюджета)
- tokens used: ~8650 из 96000 доступных

## Subagent Architecture (designed)

Один агент на каждый тип артефакта. Каждый subagent:
1. Имеет свой skill set (отфильтрованный по домену)
2. Запрашивает RAG с domain-specific keywords + time window
3. Генерирует domain-specific mini-report
4. Orchestrator мержит mini-reports в финальный отчёт

7 subagents (src/agents/subagents.py):
- evtx_agent (weight=2.0): Security/System/Application EVTX
- registry_agent (weight=1.5): persistence, Amcache, ShimCache, UserAssist
- mft_agent (weight=1.5): file timeline, malware drop, encryption
- prefetch_agent (weight=1.0): execution history
- network_agent (weight=1.5): source IPs, logon correlation
- user_activity_agent (weight=1.0): UserAssist, browser, recently used
- hayabusa_agent (weight=1.0): Sigma rule matches

Budget allocation: total_budget распределяется по subagents пропорционально
context_weight. EVTX получает больше всех (богатый источник), prefetch меньше.

## Hayabusa Integration (implemented: parser + chunker)

Hayabusa (https://github.com/Yamato-Security/hayabusa) - быстрый анализатор
Windows Event Log, использует Sigma rules для детекции.

Pipeline:
```
[EVTX files] -> hayabusa csv-timeline -p super-verbose -> alerts.csv
-> parse_hayabusa_csv() -> normalized events (source="SIGMA")
-> hayabusa_events_to_chunks() -> RAG chunks with MITRE ATT&CK tags
-> hayabusa_agent queries RAG -> sigma alerts report
```

Преимущества:
- Sigma rules = community-maintained, battle-tested (3000+ rules)
- No hallucination: rule match = deterministic detection
- MITRE ATT&CK tags включены в metadata
- Комплементарно LLM: hayabusa находит известные паттерны, LLM коррелирует

Реализовано:
- src/pipeline/hayabusa.py: parse_hayabusa_csv(), hayabusa_events_to_chunks()
- Sigma events source="SIGMA", с MITRE tactics/tags в metadata
- Docker: yamatosecurity/hayabusa image
- TODO: интеграция в pipeline runner, hayabusa subagent skill

## Threat Intelligence Integration

### IOC Enrichment через VirusTotal
- После того как агент нашёл IOC в RAG hits (IPs, file hashes, domains, service names),
  автоматически обогащать их через VirusTotal API
- VT API v3: /files/{hash}, /ip_addresses/{ip}, /domains/{domain}
- Результат enrichment добавлять в отчёт: detection ratio, tags, popular threat labels
- Гипотеза: VT enrichment даст агенту контекст о malware family
  (например, HYlugqMY.exe -> "Cobalt Strike" или "ransomware family X"),
  что улучшит attribution и TTP mapping

### TI-коннектор к платформам угроз
- Коннектор к TI-платформе (MISP, OpenCTI, ThreatFox, AlienVault OTX)
- Выгрузка IOA (Indicators of Attack) и IOC (Indicators of Compromise) по кейсу
- Сопоставление выгруженных IOC с артефактами в триаже
- MISP API: GET /events, GET /attributes, POST /attributes/search
- ThreatFox: https://threatfox-api.abuse.ch/api/v1/ (бесплатный, без ключа)
- AlienVault OTX: https://otx.alienvault.com/api/v1/ (нужен ключ)
- Гипотеза: если TI-платформа уже имеет IOA/IOC по данной APT-группе,
  агент может смапить их на артефакты триажа и подтвердить/опровергнуть
  принадлежность к конкретной кампании

### LLM-wiki TI-отчёты -> TTP mapping
- Ингест threat-intel отчётов (The DFIR Report, Mandiant, CISA advisories)
  в wiki-turboVEC (заложено в архитектуре, docs/llm_wiki.md)
- При нахождении IOC в триаже -> запрос к wiki-turboVEC -> поиск похожих
  TTPs/IOCs в изученных отчётах
- Гипотеза: если в триаже найден BTOBTO + %COMSPEC% + __output pattern,
  wiki-поиск должен вернуть отчёты про Impacket smbexec с описанием техники,
  что даст агенту готовый TTP mapping без обращения к внешним API

### Автоматический TTP extraction из отчётов
- Парсер threat-intel отчётов (PDF/HTML) через LLM-экстрактор
- Извлечение: MITRE ATT&CK IDs, IOC list, narrative, tool names
- Нормализация в JSON-схему (docs/llm_wiki.md)
- Индексация в wiki-turboVEC
- Приоритет: The DFIR Report (end-to-end DFIR), CISA advisories, Mandiant

### Mapping артефактов триажа на TTPs
- После нахождения IOC в триаже -> автоматический mapping на MITRE ATT&CK
  через wiki-turboVEC (найти отчёты с похожими IOC/TTP)
- Вывод: "Найденный BTOBTO pattern соответствует T1569.002 (Service Execution),
  описан в отчёте The DFIR Report #42, используется APT-X"
- Гипотеза: это даст агенту возможность не только находить артефакты,
  но и объяснять их связь с известными техниками атак

## Архитектура

### Коннектор-слой (TI Connectors)
```
[RAG hits with IOCs]
       |
       v
[TI Connector Layer]
  ├── VirusTotal connector (API v3, hash/IP/domain lookup)
  ├── MISP connector (events/attributes search)
  ├── ThreatFox connector (free, abuse.ch)
  ├── AlienVault OTX connector (pulse search)
  └── LLM-wiki connector (internal wiki-turboVEC)
       |
       v
[Enrichment results -> merged into agent report]
```

### Интерфейс TI-коннектора
```python
class TIConnector(Protocol):
    def lookup_ioc(self, ioc_type: str, value: str) -> TIResult: ...
    def search_ttPs(self, artifacts: list[dict]) -> list[TTPMatch]: ...

@dataclass
class TIResult:
    ioc: str
    ioc_type: str  # ip, hash, domain, service_name
    source: str    # "virustotal", "misp", "threatfox", "wiki"
    verdict: str   # "malicious", "suspicious", "clean", "unknown"
    tags: list[str]
    mitre_ttps: list[str]
    malware_family: str | None
    raw: dict
```

### Интеграция в пайплайн
1. Агент находит IOC в RAG hits ( IPs, hashes, service names)
2. IOC enrichment: каждый IOC -> TI-коннектор -> TIResult
3. TTP mapping: TIResult.mitre_ttps + wiki-turboVEC -> подтверждённые TTPs
4. Enrichment results добавляются в промпт агента
5. Агент генерирует отчёт с TI-контекстом

## Приоритеты

1. LLM-wiki ингест первых 20-30 отчётов (The DFIR Report, CISA)
2. ThreatFox коннектор (бесплатный, без ключа, быстрый win)
3. VirusTotal коннектор (нужен API key, но мощный enrichment)
4. MISP коннектор (для команд с MISP-инфраструктурой)
5. Автоматический TTP extraction из PDF/HTML отчётов
6. Mapping артефактов на TTPs через wiki-turboVEC

## Открытые вопросы

- Кэширование TI-запросов (не дёргать VT повторно для того же hash)
- Rate limits: VT = 4 req/min (free), OTX = 10 req/min
- Конфиденциальность: отправка IOC в cloud TI - допустимо ли для DFIR-кейса?
  (Альтернатива: локальный MISP)
- Как мержить conflicting verdicts из разных TI-источников?
- Авто-extraction TTPs из PDF: какой LLM использовать? (glm-5.2 через Ollama Cloud)