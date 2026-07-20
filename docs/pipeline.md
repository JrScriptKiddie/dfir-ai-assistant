# Пайплайн обработки артефактов

## Назначение

Превратить сырые триаж-артефакты в супертаймлайн, пригодный для индексации в RAG. Пайплайн детерминированный, не использует LLM на этом этапе.

## Этапы

### 1. Приём артефактов

Входы (папка `data/triage/<case_id>/`):
- Образы дисков: .e01, .raw, .dd, .vmdk, .qcow2
- Наборы артефактов: KAPE-дампы, Velociraptor-коллекции, ручные выгрузки
- Отдельные файлы: .evtx, registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY), prefetch (*.pf), shimcache, Amcache, SRUM, browser history (Chrome/Edge/Firefox SQLite), log files

Каждый кейс = отдельная папка. Метаданные кейса записываются в `data/triage/<case_id>/case.json`:
- case_id (UUID)
- название инцидента
- дата поступления
- источник сбора (инструмент)
- хэш-сумма триаж-пакета (chain of custody)

### 2. Прогон plaso (Docker)

Контейнер `dfir-plaso` (см. docker/Dockerfile.plaso):
- Базовый образ: Ubuntu с установленным plaso (log2timeline, pinfo, psort)
- Монтирование: `data/triage/<case_id>` -> `/evidence` (read-only), `data/timelines/<case_id>` -> `/output` (rw)

Шаги внутри контейнера:
1. `log2timeline.py --storage-file /output/<case_id>.plaso /evidence`
   - Парсит артефакты, создаёт plaso-хранилище
   - Параметры: `--parsers "win7,winreg,webhist,evtx"` (настраивается per case)
   - VSS: `--vss_stores combined` если нужно
2. `pinfo.py /output/<case_id>.plaso` - метаданные/статистика парсинга
3. `psort.py -o jsonl -w /output/<case_id>.timeline.jsonl /output/<case_id>.plaso`
   - Выход: JSONL, одна строка = одно событие таймлайна
4. Альтернативный выход: CSV через `-o l2tcsv` для обратной совместимости

Запуск:
`docker run --rm -v $(pwd)/data/triage/<case_id>:/evidence:ro -v $(pwd)/data/timelines/<case_id>:/output dfir-plaso <case_id>`

### 3. Постобработка таймлайна

Python-модуль `src/pipeline/normalizer.py`:
- Читает JSONL
- Нормализует поля: timestamp (UTC), source, sourcetype, message, user, host, parser
- Дедупликация событий (по кортежу ключевых полей)
- Фильтрация шума (опционально: exclude-list по sourcetype)
- Выход: `data/processed/<case_id>/events.jsonl` (нормализованный, дедуплицированный)

### 4. Подготовка к RAG

Python-модуль `src/rag/chunker.py`:
- Принцип: **один лог = один элемент RAG**
- Для каждого события формируется chunk:
  - text: читаемое текстовое представление события
  - metadata: case_id, timestamp, source, sourcetype, parser, host, user, raw_hash
  - id: детерминированный (hash(case_id + timestamp + source + message))
- Выход: `data/processed/<case_id>/chunks.jsonl`

### 5. Эмбеддинг и загрузка в turboVEC

Python-модуль `src/rag/embedder.py`:
- Читает chunks.jsonl
- Вызывает эмбеддер (переключаемый: OpenAI, Ollama embeddings, локальные модели)
- Записывает в turboVEC (см. rag_design.md)
- Метаданные chunk сохраняются рядом с вектором

## Параметры конфигурации

`config/pipeline.yaml` (будет добавлен):
- plaso_parsers: список парсеров или "win7"
- vss_stores: "none" | "combined" | "all"
- exclude_sourcetypes: []
- embedder: "ollama" | "openai"
- embedding_model: "nomic-embed-text" | "text-embedding-3-small"

## Ошибка и валидация

- plaso exit code != 0 -> логируем, пайплайн стопается, кейс помечается failed
- Нулевой выходной JSONL -> warning, проверка что evidence был непустой
- Чанк с пустым message -> skip с warning
- Хэш chunks.jsonl сравнивается с hash таймлайна (целостность)