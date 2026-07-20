# data/

Содержит рабочие данные проекта. Содержимое gitignored, кроме README.

## Структура

- `triage/<case_id>/` - сырые триаж-артефакты по кейсам
  - `case.json` - метаданные кейса (UUID, описание, хэш)
  - файлы артефактов
- `timelines/<case_id>/` - выход plaso
  - `<case_id>.plaso` - хранилище plaso
  - `<case_id>.timeline.jsonl` - супертаймлайн
  - `<case_id>.pinfo.txt` - статистика парсинга
- `processed/<case_id>/` - обработанные данные для RAG
  - `events.jsonl` - нормализованные события
  - `chunks.jsonl` - chunks для RAG
  - `turbovec/` - векторный индекс кейса
  - `report.md` - отчёт агента
- `wiki/turbovec/` - общий векторный индекс LLM-wiki

## Chain of custody

Для каждого кейса в `triage/<case_id>/case.json` фиксируется:
- время приёма
- источник сбора
- хэш триаж-пакета
- аналитик

Evidence не модифицируется после приёма. plaso работает с read-only монтированием.