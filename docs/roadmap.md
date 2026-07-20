# Roadmap / TO-DO

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