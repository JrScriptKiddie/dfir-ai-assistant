# LLM-wiki из threat-intel отчётов

## Идея

Собрать корпус публичных threat-intel отчётов (APT, ransomware, red-team writeups), нормализовать их в единую структуру и индексировать в тот же RAG, что и события таймлайна. Это даёт агенту возможность:
- Сопоставлять свежие события с известными TTPs
- Извлекать IOCs (хэши, IP, домены, mutexes, registry keys) из отчётов
- Опираться на подтверждённую информацию, а не на общие знания модели

## Формат статьи wiki

Каждый отчёт приводится к одному JSON-документу:

```json
{
  "id": "<sha1(title|author|published)>",
  "title": "Operation Rustic Furniture",
  "author": "Mandiant",
  "published": "2024-05-12",
  "url": "https://...",
  "tags": ["APT41", "ransomware", "China-nexus"],
  "ttps": [
    {"mitre_id": "T1059.001", "name": "PowerShell", "context": "used for initial bootstrap"},
    {"mitre_id": "T1547.001", "name": "Run Keys", "context": "persistence via HKCU\\...\\Run"}
  ],
  "iocs": [
    {"type": "sha256", "value": "abcdef..."},
    {"type": "ipv4", "value": "203.0.113.5"},
    {"type": "domain", "value": "ccbad.example"},
    {"type": "registry_key", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update"},
    {"type": "mutex", "value": "Global\\\\RusticMutex"}
  ],
  "narrative": "Краткое изложение инцидента и хода расследования",
  "chunks": [
    {"id": "<sha1>", "text": "абзац 1 нарратива", "metadata": {...}},
    {"id": "<sha1>", "text": "абзац 2 нарратива", "metadata": {...}}
  ]
}
```

`chunks` - это фрагменты нарратива и описания TTP, каждый маппится на тот же формат chunk, что и события таймлайна, и индексируется в отдельный wiki-индекс turboVEC.

## Маппинг на RAG

- Wiki-индекс живёт в `data/wiki/turbovec/`
- События кейса - в `data/processed/<case_id>/turbovec/`
- При запросе агент может указать scope: events | wiki | both
- В ответе hit помечается `source: "event"` или `source: "wiki"`

## Источники отчётов

См. `docs/threat_intel_sources.md`.

## Парсер отчётов

Модуль `src/wiki/ingest.py`:
- Принимает PDF/HTML/Markdown отчёт
- Извлекает текст (pdfplumber / trafilatura / markdown)
- LLM-экстрактор: структурирует в JSON-схему выше (TTPs, IOCs, narrative)
- Валидация схемы (pydantic)
- Чанкование нарратива
- Эмбеддинг и загрузка в wiki-turboVEC

## Особенности работы с wiki

- Wiki - **память агента о внешнем мире**, не о конкретном инциденте
- Wiki пополняется независимо от кейсов, без пересбора кейс-RAG
- При цитировании wiki-статьи агент указывает `report.id` и `chunk.id`
- Wiki-индекс можно валидировать: для каждой статьи есть ground-truth TTPs/IOCs, можно гонять retrieval-тесты