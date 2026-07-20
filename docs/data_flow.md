# Потоки данных между компонентами

## Последовательность обработки одного кейса

```
1. Аналитик кладёт триаж-пакет в data/triage/<case_id>/
   - создаётся case.json с метаданными и хэшем

2. src/pipeline/runner.py:
   - читает case.json
   - запускает docker-контейнер dfir-plaso
     - mount data/triage/<case_id> -> /evidence (ro)
     - mount data/timelines/<case_id> -> /output (rw)
     - log2timeline.py -> <case_id>.plaso
     - pinfo.py (статистика)
     - psort.py -o jsonl -> <case_id>.timeline.jsonl
   - контейнер завершается и удаляется (--rm)

3. src/pipeline/normalizer.py:
   - data/timelines/<case_id>/<case_id>.timeline.jsonl
   - нормализация полей, дедупликация
   - data/processed/<case_id>/events.jsonl

4. src/rag/chunker.py:
   - data/processed/<case_id>/events.jsonl
   - 1 event -> 1 chunk (text + metadata)
   - data/processed/<case_id>/chunks.jsonl

5. src/rag/embedder.py + src/rag/turbovec.py:
   - data/processed/<case_id>/chunks.jsonl
   - эмбеддинг
   - data/processed/<case_id>/turbovec/ (индекс + metadata.json)

6. src/agents/dfir_agent.py:
   - case_id + описание инцидента
   - запросы к turboVEC (events) + к wiki-turboVEC
   - формирование отчёта
   - data/processed/<case_id>/report.md
```

## Поток wiki-ингеста (независимый от кейсов)

```
1. Аналитик кладёт отчёт в wiki/reports/<report_id>/original.(pdf|html|md)

2. src/wiki/ingest.py:
   - извлекает текст
   - LLM-экстрактор -> wiki_article.json (TTPs, IOCs, narrative, chunks)
   - валидация схемы
   - wiki/reports/<report_id>/article.json

3. src/wiki/indexer.py:
   - article.json -> chunks
   - эмбеддинг
   - data/wiki/turbovec/ (общий wiki-индекс)
```

## Состояния кейса

`data/triage/<case_id>/case.json` содержит поле `status`:
- new: артефакты загружены
- processing_plaso: запущен контейнер
- plaso_done: таймлайн готов
- normalizing: постобработка
- chunking: подготовка RAG
- indexing: загрузка в turboVEC
- ready: RAG готов, можно запускать агента
- agent_run: агент работает
- reported: отчёт готов
- failed: ошибка на каком-то этапе (см. error.log)
```

## Идемпотентность

- Повторный запуск plaso по тому же evidence -> перезаписывает .plaso (детерминированный прогон)
- normalizer / chunker - детерминированные, повторный запуск перезаписывает выход
- turboVEC rebuild: опция `--rebuild` пересоздаёт индекс с нуля, иначе - инкрементальное добавление новых chunks (по chunk.id)

## Хранение и размеры

- events.jsonl: ~1-10 МБ на типичный кейс (десятки тыс. событий)
- chunks.jsonl: ~2-20 МБ (text чуть длиннее сырого события)
- turboVEC индекс: ~N * dim * 4 байт (например, 100k * 768 * 4 = 300 МБ)
- wiki: суммарно ~1-5 ГБ на корпус из тысяч отчётов