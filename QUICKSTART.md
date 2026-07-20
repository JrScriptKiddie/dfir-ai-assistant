# Quick Start

## 1. Clone и установка

```bash
git clone https://github.com/JrScriptKiddie/dfir-ai-assistant.git
cd dfir-ai-assistant

# Установка зависимостей (Python 3.11+)
pip install -e ".[dev]"

# Проверка что всё работает
pytest -q
```

Если PEP 668 блокирует (Debian/Ubuntu):

```bash
pip install -e ".[dev]" --break-system-packages
```

Или через venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 2. Настройка LLM

Скопируйте конфиг и заполните API-ключ:

```bash
cp .env.example .env
```

### Вариант A: Ollama Cloud (онлайн, без локальной установки)

Получите ключ на https://ollama.com/settings

```ini
# .env
LLM_BACKEND=ollama
OLLAMA_HOST=https://ollama.com/v1
OLLAMA_API_KEY=ваш_ключ_от_ollama_cloud
OLLAMA_MODEL=glm-5.2
```

Доступные модели: glm-5.2, qwen3.5:397b, deepseek-v4-pro, kimi-k2.7-code, и др.
Список: `curl -H "Authorization: Bearer $OLLAMA_API_KEY" https://ollama.com/v1/models`

### Вариант B: Локальный Ollama

```bash
# Установка: https://ollama.com
ollama serve &
ollama pull qwen2.5:14b
```

```ini
# .env
LLM_BACKEND=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:14b
```

### Вариант C: OpenAI-совместимый API

Любой провайдер с OpenAI-compatible endpoint (OpenAI, vLLM, LM Studio, и т.д.):

```ini
# .env
LLM_BACKEND=openai
OPENAI_API_BASE=https://api.openai.com/v1
OPENAI_API_KEY=sk-ваш_ключ
OPENAI_MODEL=gpt-4o-mini
```

### Вариант D: Через переменные окружения (без .env)

```bash
export LLM_BACKEND=ollama
export OLLAMA_HOST=https://ollama.com/v1
export OLLAMA_API_KEY=ваш_ключ
export OLLAMA_MODEL=glm-5.2
```

## 3. Установка plaso

### Через pip (быстро, без Docker)

```bash
pip install plaso
# Проверка
log2timeline --version
```

### Через Docker (изолированно)

```bash
docker build -t dfir-plaso -f docker/Dockerfile.plaso docker/
# Проверка
docker run --rm dfir-plaso log2timeline --version
```

## 4. Полный пайплайн на реальном кейсе

### Шаг 1: Подготовка данных

Положите триаж-артефакты в папку кейса:

```
data/triage/my-case/
  case.json          # метаданные кейса
  $MFT
  config/SYSTEM
  config/SOFTWARE
  config/SAM
  config/SECURITY
  Users/<user>/NTUSER.DAT
  winevt/Logs/Security.evtx
  winevt/Logs/System.evtx
  AppCompat/Programs/Amcache.hve
  ...
```

Минимальный пример case.json:

```json
{
  "case_id": "my-case",
  "title": "Brief description",
  "received_at": "2026-01-01",
  "source": "manual triage",
  "status": "new"
}
```

### Шаг 2: plaso -> таймлайн

```bash
# Через pip-установленный plaso:
log2timeline --storage-file data/timelines/my-case/my-case.plaso \
  --parsers "winevtx,winreg,prefetch,filestat" \
  data/triage/my-case/

psort -o json_line -w data/timelines/my-case/my-case.timeline.jsonl \
  data/timelines/my-case/my-case.plaso

# Через Docker:
docker run --rm \
  -v $(pwd)/data/triage/my-case:/evidence:ro \
  -v $(pwd)/data/timelines/my-case:/output \
  dfir-plaso my-case
```

### Шаг 3: Нормализация -> чанки -> turboVEC

```bash
python3 -c "
from src.pipeline.normalizer import normalize_file
from src.rag.tfidf_embedder import TfidfEmbedder
from src.rag.indexer import build_index_from_events

# Нормализация
stats = normalize_file(
    'data/timelines/my-case/my-case.timeline.jsonl',
    'data/processed/my-case/events.jsonl',
    'my-case'
)
print('Normalized:', stats)

# Индексация в turboVEC
embedder = TfidfEmbedder(dim=512)
store = build_index_from_events(
    'data/processed/my-case/events.jsonl',
    'my-case',
    'data/processed/my-case/turbovec',
    embedder
)
print('Index:', store.stats())
"
```

### Шаг 4: Запуск агента

```bash
# Incident mode (с описанием инцидента):
python -m src.agents.cli incident \
  --case my-case \
  --incident "Files encrypted, suspicious services installed" \
  --k 25

# Compromise assessment (автономно, без описания):
python -m src.agents.cli assess \
  --case my-case \
  --k 25
```

Отчёты сохраняются в:
- `data/processed/my-case/report_incident.md`
- `data/processed/my-case/report_assessment.md`

## 5. Использование через AI-агентов (Hermes, Codex, и т.д.)

DFIR AI Assistant спроектирован как Python-библиотека. Любой AI-агент
с доступом к shell может вызывать пайплайн и агента.

### Hermes Agent

Добавьте в skills или используйте напрямую из промпта:

```
# Hermes skill (skills/dfir/analyze.md)
---
name: dfir-analyze
description: Run DFIR analysis on a triage case
---
Run the DFIR pipeline:
1. python -m src.pipeline.runner <case_id>
2. python -m src.agents.cli assess --case <case_id> --k 25
3. Read data/processed/<case_id>/report_assessment.md
4. Summarize findings for the user
```

Или вызов из Python (внутри Hermes tool):

```python
from src.agents.dfir_agent import DFIRAgent
from src.agents.llm import get_llm
from src.rag.turbovec import TurboVec
from src.rag.tfidf_embedder import TfidfEmbedder

store = TurboVec.load("data/processed/my-case/turbovec")
embedder = TfidfEmbedder.load("data/processed/my-case/turbovec/embedder.npz")
llm = get_llm()  # читает .env / переменные окружения

agent = DFIRAgent(store=store, embedder=embedder, llm=llm, k=25)
result = agent.run_assessment()
print(result.report)
print(f"Skills used: {result.skills_used}")
print(f"Hits: {len(result.hits_used)}")
```

### Codex / Claude Code / другие CLI-агенты

Codex и подобные агенты работают через shell-команды. Пайплайн запускается так:

```bash
# Полный пайплайн одной командой:
python -m src.pipeline.runner my-case

# Агент (assessment):
python -m src.agents.cli assess --case my-case --k 25

# Агент (incident с описанием):
python -m src.agents.cli incident --case my-case \
  --incident "Ransomware detected, files encrypted" --k 25
```

Промпт для Codex/Claude:

```
You have access to a DFIR analysis tool. To investigate a case:
1. Run: python -m src.pipeline.runner <case_id>
   This processes triage artifacts through plaso and builds a RAG index.
2. Run: python -m src.agents.cli assess --case <case_id> --k 25
   This runs autonomous compromise assessment.
3. Read the report at data/processed/<case_id>/report_assessment.md
4. Present findings to the user with key IOCs and timeline.
```

### Переключение LLM на лету

```bash
# Ollama Cloud:
LLM_BACKEND=ollama OLLAMA_HOST=https://ollama.com/v1 \
  OLLAMA_API_KEY=xxx OLLAMA_MODEL=glm-5.2 \
  python -m src.agents.cli assess --case my-case

# Локальный Ollama:
LLM_BACKEND=ollama OLLAMA_HOST=http://localhost:11434 \
  OLLAMA_MODEL=qwen2.5:14b \
  python -m src.agents.cli assess --case my-case

# OpenAI:
LLM_BACKEND=openai OPENAI_API_KEY=sk-xxx OPENAI_MODEL=gpt-4o-mini \
  python -m src.agents.cli assess --case my-case
```

## 6. Структура проекта

```
dfir-ai-assistant/
  .env.example          # шаблон конфигурации -> скопируйте в .env
  pyproject.toml        # зависимости
  src/
    pipeline/           # plaso -> normalize -> events.jsonl
      normalizer.py     # plaso json_line -> normalized events
      runner.py         # full pipeline orchestrator
    rag/                # RAG + turboVEC
      turbovec.py       # vector store (numpy, keyword search, time filters)
      chunker.py        # 1 event = 1 chunk
      embedder.py       # embedder factory (dummy, ollama, openai)
      tfidf_embedder.py # TF-IDF embedder (numpy-only, persistable)
      indexer.py        # build/load/query index
    agents/             # DFIR agent
      dfir_agent.py     # two modes: incident + assessment
      skills.py         # 12 DFIR skills (hybrid retrieval)
      plaso_knowledge.py # 58 parsers, 7 presets, DFIR metadata
      llm.py            # LLM provider (Ollama local/cloud, OpenAI)
      cli.py            # CLI: incident / assess subcommands
  docker/               # plaso container
  docs/                 # architecture, pipeline, skills, plaso docs
  tests/                # 39 tests
```

## 7. Troubleshooting

**`ModuleNotFoundError: No module named 'src'`**
Запускайте из корня проекта: `cd dfir-ai-assistant && python -m src.agents.cli ...`

**`turboVEC index not found`**
Сначала прогоните пайплайн (шаги 2-3), потом запускайте агента.

**`httpx.HTTPStatusError: 401`**
Проверьте API-ключ в .env или переменных окружения.

**`plaso: command not found`**
Установите: `pip install plaso` или через Docker.

**Ollama Cloud: embeddings endpoint not found**
Ollama Cloud не поддерживает /v1/embeddings. Используется TF-IDF embedder
(по умолчанию). Для нейросетевых эмбеддингов используйте локальный Ollama
с nomic-embed-text или OpenAI text-embedding-3-small.