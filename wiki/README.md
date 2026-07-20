# DFIR AI Assistant - Wiki

База знаний проекта, наполняется из threat-intel отчётов и ручных конспектов.

## Структура

- `ttp/` - каталог тактик и техник (маппинг на MITRE ATT&CK)
  - каждый TTP - отдельный markdown с описанием, примерами, детекции
- `iocs/` - каталоги IOC из отчётов (по группировкам: apt, ransomware, etc.)
- `reports/` - конспекты изученных threat-intel отчётов
  - каждый отчёт - отдельная папка с original + article.json
- `playbooks/` - плейбуки реагирования по типам инцидентов
  - ransomware.yml, lateral_movement.yml, initial_access.yml, etc.

## Принцип наполнения

1. Аналитик находит подходящий threat-intel отчёт
2. Кладёт оригинал в `wiki/reports/<report_id>/original.(pdf|html|md)`
3. Запускает `python -m dfir_assistant.wiki.ingest <report_id>`
4. Парсер через LLM извлекает TTPs/IOCs/narrative и формирует article.json
5. Статья индексируется в wiki-turboVEC

## Согласование с RAG

См. `docs/llm_wiki.md` - формат статьи wiki маппится на chunk-формат и индексируется в тот же turboVEC API, что и события кейса.

## Текущее состояние

Заготовка структуры. Первые отчёты - в очереди на ингест.