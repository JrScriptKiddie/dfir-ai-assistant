# Roadmap / TO-DO

## Проблемы и ограничения одного агента

В ходе разработки и тестирования на реальном кейсе SRV.nebo.ru мы столкнулись
с рядом проблем, которые мотивируют переход к multi-agent архитектуре.

### Проблема 1: Retrieval отсекает IOC по score

Симптом: данные есть в индексе (172.16.2.20 в 27 событиях, install.exe в 31,
kirill в 146), но не попадают в top-k hits, потому что TF-IDF score для
точных IOC совпадений ниже, чем для семантически похожих registry events.

Решение (текущее): explicit IOC injection - 16 ключевых IOC keywords ищутся
индивидуально, гарантированно попадают в результат независимо от score.
Но это hack: список IOC hardcoded, не масштабируется на новые кейсы.

Корневая причина: один агент пытается покрыть все домены (EVTX, registry,
MFT, network) одним retrieval pass. Score-ranking работает для одного
домена, но跨-domain сравнение некорректно (registry event с 5 keyword
совпадениями получает score выше чем EVTX event с 1 IOC совпадением).

Решение (архитектурное): subagents. Каждый subagent работает только в
своём домене, score-ranking корректен внутри домена.

### Проблема 2: Context dilution

Симптом: при 100 hits в промпте LLM упускает часть IOC, хотя они есть
в hits. Например, install.exe и ANONYMOUS LOGON были в hits, но LLM
не упомянул их в отчёте.

Причина: 100 hits = ~6250 tokens. LLM "теряет" детали в длинном контексте,
особенно когда разные домены смешаны (registry noise 2013 года рядом
с EVTX incident events 2021 года).

Решение: subagents с domain-specific контекстом. EVTX subagent видит
только EVTX events, registry subagent - только registry. Меньше шума =
лучше качество анализа. Orchestrator получает concise mini-reports,
не raw hits.

### Проблема 3: Time-window detection неточна

Симптом: two-phase retrieval (broad -> detect window -> time-sliced)
иногда отсекает релевантные события. На SRV.nebo.ru окно определилось
как 2021-04-19 07:09-08:35, но events с source IPs (07:06:29) и kirill
logon (07:37:14) попали на границу и были отфильтрованы.

Причина: один агент определяет окно по всем доменам одновременно.
Registry events (2013-2020) смещают кластеризацию, EVTX events
разбросаны по разным timestamp_desc (Content Modification Time,
Last registered Time), что усложняет кластеризацию.

Решение: каждый subagent определяет своё окно независимо.
EVTX subagent кластеризует только EVTX timestamps, MFT subagent -
только MFT timestamps. Окно может отличаться по доменам.

### Проблема 4: Нет детерминированной детекции

Симптом: LLM может найти BTOBTO pattern и сопоставить с Impacket smbexec,
но это вероятностный анализ. Нет гарантии что правило сработает на
другом кейсе с тем же паттерном.

Причина: один агент полагается на LLM для pattern matching.
LLM не детерминирована, может пропустить известный паттерн.

Решение: hayabusa subagent. Sigma rules = детерминированная детекция.
Если правило "Impacket smbexec BTOBTO" существует в Sigma, оно сработает
всегда. LLM добавляет корреляцию и интерпретацию, но не заменяет rules.

### Проблема 5: Один промпт для всех доменов

Симптом: system prompt содержит инструкции для всех доменов одновременно
("ищи service installations", "ищи Run keys", "ищи file modifications",
"ищи source IPs"). LLM не может одинаково хорошо анализировать все домены
в одном промпте - внимание распределяется, качество падает.

Решение: каждый subagent имеет свой промпт, оптимизированный для домена.
EVTX prompt: "анализируй Event ID 4624/4625/7045/4688, извлекай source IP,
logon type, user". Registry prompt: "анализируй Run keys, Amcache, UserAssist,
ShimCache". MFT prompt: "ищи file creation перед encryption, mass modifications".

### Проблема 6: Нет cross-domain корреляции

Симптом: один агент находит install.exe в UserAssist (REG domain) и
PSEXESVC в EVTX, но не коррелирует их ("install.exe запущен пользователем
kirill через RDP, PsExec использовался adm_pavel для lateral movement").

Причина: один агент не имеет явного механизма cross-domain correlation.
LLM пытается делать это в голове, но при 100 hits это не работает.

Решение: orchestrator получает mini-reports от subagents и делает
явную корреляцию: "EVTX subagent: kirill RDP type 10 from 172.16.2.20
at 07:52. MFT subagent: install.exe created at 08:04. UserActivity
subagent: install.exe executed by kirill. Correlation: kirill launched
ransomware via RDP after adm_pavel used PsExec for lateral movement."

### Проблема 7: TF-IDF embeddings не семантические

Симптом: "logon authentication" не находит 4624 events, потому что
TF-IDF не понимает семантику, только keyword overlap.

Причина: Ollama Cloud не предоставляет embeddings endpoint.
sentence-transformers требует torch (~2 GB).

Решение (текущее): hybrid retrieval (TF-IDF + keyword search + IOC injection).
Решение (будущее): нейросетевой embedder (nomic-embed-text через локальный
Ollama, или bge-small-en-v1.5 через sentence-transformers когда torch доступен).

### Ограничения одного агента (резюме)

| Ограничение | Симптом | Решение |
|-------------|---------|---------|
| Score-ranking cross-domain | IOC отсекаются | Subagents per domain |
| Context dilution | LLM упускает IOC | Domain-specific контекст |
| Time-window неточность | Граничные events теряются | Per-domain window detection |
| Нет детерминированной детекции | LLM может пропустить паттерн | Hayabusa Sigma rules |
| Один промпт для всех | Внимание распределяется | Domain-specific prompts |
| Нет cross-domain корреляции | Связи между доменами теряются | Orchestrator correlation |
| TF-IDF не семантический | Semantic queries промахиваются | Нейросетевой embedder (TODO) |

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

## Sanitizer / Masking Pipeline (implemented)

Проблема: forensic logs могут содержать пароли, токены, хэши, PII.
Отправка в cloud LLM (Ollama Cloud, OpenAI) создаёт риск утечки.

Решение: src/pipeline/sanitizer.py - препроцессинг логов перед RAG.

Пайплайн:
```
[events.jsonl] -> Sanitizer.sanitize_events_file() -> sanitized.jsonl
-> chunker -> RAG (LLM видит только masked данные)
```

Стратегии маскирования:
- REDACT: [REDACTED:TYPE] (passwords, API keys, JWT, credit cards, private keys)
- HASH: [HASH:abc123] (NTLM/SHA-1/SHA-256 - preserves correlation, hides value)
- PARTIAL: 172.16.[***].20 (IPs), jo***@company.com (emails)
- TOKENIZE: [IP_001] (stable per unique value - preserves correlation)

Конфигурация:
- IPs по умолчанию НЕ маскируются (DFIR needs IPs)
- Token map сохраняется для de-anonymization авторизованным аналитиком
- Маскируются: passwords, NTLM/SHA hashes, API keys, JWT, emails, credit cards, private keys

## Hallucination Control и Human-in-the-Loop

### Проблема: галлюцинации в DFIR

В DFIR галлюцинация модели (выдуманный CVE, ошибочная интерпретация флага
команды, придуманный IOC) может привести к неверному решению по изоляции
хоста или пропуску закрепления вредоноса. Цена ошибки выше чем в chatbot.

### Strict Grounding (TODO)

Каждый вывод в отчёте ассистента должен содержать прямую ссылку на
конкретную строку лога или артефакт:
- "Процесс install.exe запущен [chunk_id=2a6482f1052dcdd0, EventID 4688]"
- "Сервис McBz установлен [chunk_id=5be9b34ade90605c, EventID 7045]"
- Без ссылки = гипотеза, не факт

Реализация:
1. Post-generation validation: парсим отчёт LLM, извлекаем все [chunk_id] ссылки
2. Проверяем что каждый chunk_id существует в RAG hits
3. Проверяем что утверждаемое в тексте соответствует содержимому chunk
4. Помечаем unsupported claims как "UNVERIFIED" в отчёте
5. Confidence score: % утверждений с валидной ссылкой

```python
class GroundingValidator:
    def validate(self, report: str, hits: list[Hit]) -> GroundingResult:
        """Check that all claims in report reference valid chunk_ids."""
        cited_ids = extract_citations(report)
        hit_ids = {h.chunk.id for h in hits}
        valid = cited_ids & hit_ids
        invalid = cited_ids - hit_ids
        unsupported = find_unsupported_claims(report, hits)
        return GroundingResult(
            cited=valid, invalid=invalid, unsupported=unsupported,
            confidence=len(valid) / max(len(cited), 1)
        )
```

### Copilot вместо Autopilot (TODO)

Ассистент предлагает целевые действия (playbooks) и формирует CLI-команды
для реагирования, но финальное исполнение оставляет за оператором.

Режимы работы:
1. ANALYZE (текущий): только анализ и отчёт, никаких действий
2. RECOMMEND (TODO): отчёт + playbook recommendations (CLI commands)
3. EXECUTE (future, requires --approve flag): выполняет playbook с подтверждением

Playbook recommendations в отчёте:
```
## RECOMMENDED ACTIONS (require operator approval)

1. Isolate SRV.nebo.ru from network
   CLI: netsh interface set interface "Ethernet" admin=disable
   RISK: prevents lateral movement but may lose volatile evidence

2. Disable compromised account adm_pavel
   CLI: net user adm_pavel /active:no /domain
   RISK: may impact legitimate services using this account

3. Block SMB from 172.16.2.22
   CLI: netsh advfirewall firewall add rule name="Block-Attacker" 
        dir=in action=block remoteip=172.16.2.22
   RISK: none (attacker IP)

[!] All actions require explicit operator approval before execution.
```

Human-in-the-Loop workflow:
```
[Agent Report + Recommendations]
       |
       v
[Operator Review]
  ├── Approve action 1 -> execute
  ├── Modify action 2 -> execute modified
  ├── Reject action 3 -> skip
  └── Request more info -> agent re-analyzes
```

### Confidence Scoring (TODO)

Каждый раздел отчёта получает confidence score:
- HIGH: все утверждения имеют валидные chunk_id ссылки, >= 3 источников
- MEDIUM: есть ссылки, но < 3 источников или partial match
- LOW: утверждения без ссылок или с invalid chunk_ids
- CRITICAL: галлюцинация обнаружена (invalid chunk_id или unsupported claim)

Отчёт с confidence:
```
## FINDINGS

1. [HIGH] Service "McBz" installed with HYlugqMY.exe [chunk_id=5be9b34a]
2. [MEDIUM] Attacker used Impacket smbexec [chunk_id=7e4eca99] 
   (pattern match, tool name inferred)
3. [LOW] Initial access may have been via NTLM V1 [chunk_id=5cd0845c]
   (hypothesis, correlation weak)
```