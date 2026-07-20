# DFIR AI Assistant

Ассистент на базе ИИ для специалистов Digital Forensics & Incident Response (DFIR).

Проект ставит целью нормализовать пайплайн реагирования на инциденты: от триаж-артефактов и собранных образов до структурированного таймлайна и RAG-базы знаний, поверх которой работает агентная логика.

## Краткое описание пайплайна

1. Триаж / артефакты поступают на вход (E01, raw, evtx, plaso, JSON-дампы и т.д.)
2. Артефакты прогоняются через log2timeline / plaso в Docker-контейнере -> получается таймлайн
3. Таймлайн разбивается по принципу "один лог - один элемент" (chunk-per-event) и индексируется в RAG
4. RAG конвертируется в turboVEC - компактное векторное представление, служащее базой для агента
5. Общий DFIR-агент проводит реагирование поверх turboVEC, впоследствии дополняется сабагентами по доменам (registry, evtx, shimcache, prefetch, browser, etc.)

Дополнительно: LLM-wiki на основе изученных публичных отчётов threat-intel, маппится на тот же RAG-формат, чтобы агент мог ссылаться на known-TTPs и IOCs из отчётов при анализе свежего инцидента.

## Структура репозитория

dfir-ai-assistant/
  README.md                 - этот файл
  docs/                     - техническая документация проекта
    architecture.md         - архитектура и компоненты
    pipeline.md             - детальное описание пайплайна
    rag_design.md           - дизайн RAG и turboVEC
    agent_design.md         - дизайн агента и сабагентов
    llm_wiki.md             - дизайн LLM-wiki из threat-intel отчётов
    threat_intel_sources.md - источники отчётов для wiki
    data_flow.md            - потоки данных между компонентами
    decisions.md            - журнал архитектурных решений (ADR-стиль)
    glossary.md             - глоссарий терминов проекта
  wiki/                     - wiki-контент (статьи, TTPs, IOC-каталоги)
    README.md               - оглавление wiki
    ttp/                    - тактики и техники (маппинг на MITRE ATT&CK)
    ioc/                    - каталоги IOC из отчётов
    reports/                - конспекты изученных отчётов
    playbooks/              - плейбуки реагирования
  article/                  - внешние материалы
    author_article.md       - статья от лица автора с описанием идеи и текущего прогресса
  src/                      - исходный код
    pipeline/               - пайплайн обработки артефактов
    rag/                    - RAG и turboVEC
    agents/                 - агентная логика
    wiki/                   - инструменты работы с LLM-wiki
  docker/                   - Dockerfile и compose для plaso и других инструментов
  data/                     - данные (gitignored, кроме структуры)
    triage/                 - сырые триаж-артефакты
    timelines/              - выход plaso
    processed/              - обработанные данные для RAG
  tests/                    - тесты
  .gitignore

## Стек

- Python 3.13 (uv / venv)
- Docker (plaso/log2timeline, изолированный прогон)
- Векторное хранилище: turboVEC (см. docs/rag_design.md)
- LLM-бэкенд: переключаемый (OpenAI-совместимый API, локальные модели через Ollama)

## Быстрый старт

См. [QUICKSTART.md](QUICKSTART.md) - подробная инструкция от git clone до отчёта агента.

Кратко:

```bash
git clone https://github.com/JrScriptKiddie/dfir-ai-assistant.git
cd dfir-ai-assistant
pip install -e ".[dev]"
cp .env.example .env  # заполнить API-ключ

# 1. plaso -> таймлайн
log2timeline --storage-file data/timelines/my-case/my-case.plaso \
  --parsers "winevtx,winreg,prefetch,filestat" data/triage/my-case/
psort -o json_line -w data/timelines/my-case/my-case.timeline.jsonl \
  data/timelines/my-case/my-case.plaso

# 2. Нормализация + индексация
python -m src.pipeline.runner my-case

# 3. Агент (compromise assessment)
python -m src.agents.cli assess --case my-case --k 25
```

## Использование через AI-агентов (Hermes, Codex, Claude Code)

Пайплайн вызывается через shell-команды или Python API. См. [QUICKSTART.md](QUICKSTART.md#5-использование-через-ai-агентов-hermes-codex-и-тд).

## Лицензия

(Определить позже)

## Статус

Ранний этап: проектирование архитектуры, подготовка пайплайна и wiki-структуры.