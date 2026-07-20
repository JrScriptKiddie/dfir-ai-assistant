# Дизайн агента

## Общий DFIR-агент (первый этап)

Назначение: проводить реагирование по инциденту на основе turboVEC и wiki.

Два режима работы:

### 1. Incident Investigation (инцидент)

Аналитик даёт описание инцидента (что произошло, когда, какие артефакты собраны).
Агент использует описание для targeted retrieval и формирует отчёт по инциденту.

Вход:
- case_id
- Описание инцидента от аналитика (free text)
- Опционально: scope (заинтересованные хосты/пользователи/время)

Выход:
- Структурированный отчёт по инциденту (SUMMARY, TIMELINE, FINDINGS, HYPOTHESES, TTPs, IOCs, RECOMMENDATIONS, OPEN QUESTIONS)

### 2. Compromise Assessment (оценка компрометации)

Аналитик НЕ даёт описание инцидента. Агент самостоятельно изучает триаж,
ищет аномалии и подозрительную активность, и выдаёт саммари: скомпрометирована
система или нет, что найдено suspicious, какой риск.

Вход:
- case_id
- (без описания инцидента)

Выход:
- Compromise Assessment отчёт (ASSESSMENT SUMMARY, ANOMALIES, TIMELINE, FINDINGS, HYPOTHESES, TTPs, IOCs, RISK LEVEL, RECOMMENDATIONS, OPEN QUESTIONS)
- RISK LEVEL: Low / Medium / High / Critical с обоснованием

## Цикл работы агента

1. Парсит описание инцидента, извлекает сущности (хост, пользователь, время, тип активности)
2. Формирует первичные запросы к RAG (по сущностям + по семантике описания)
3. Анализирует hits, группирует события во времени, выявляет аномалии
4. Формирует гипотезы (initial access / persistence / lateral / exfil / etc.)
5. Для каждой гипотезы делает уточняющие запросы к RAG (targeted retrieval)
6. Сопоставляет события с wiki (известные TTPs, IOCs)
7. Генерирует отчёт с цитатами и метаданными

## Промпт-дизайн

Системный промпт (кратко):
- Роль: DFIR-аналитик, работающий с таймлайном инцидента
- Ограничение: каждое утверждение о факте должно иметь source (chunk.id из RAG)
- Без источника - только как гипотеза с явной пометкой
- Язык отчёта: настраивается (русский/английский)
- Формат отчёта: секции (Summary, Timeline, Findings, TTPs, IOCs, Recommendations, Open Questions)

## Интерфейс

CLI (первый этап):
`python -m dfir_assistant.agent run --case <case_id> --incident "описание"`

В перспективе: веб-UI с timeline-визуализацией и source-highlighting.

## Сабагенты (в перспективе)

После стабилизации общего агента планируются сабагенты по доменам артефактов:

| Сабагент         | Источник данных                          | Задача                                            |
|------------------|------------------------------------------|---------------------------------------------------|
| registry-agent   | NTUSER.DAT, SYSTEM, SOFTWARE, SAM        | Анализ persistence, autorun, recently used        |
| evtx-agent       | .evtx (Security, System, Application)    | Логины, сервисы, ошибки, аудит                    |
| prefetch-agent   | *.pf                                     | Исполняемые файлы, время запуска                  |
| shimcache-agent  | ShimCache / Amcache                      | История запусков, хэши                            |
| browser-agent    | Chrome/Edge/Firefox history              | C2-контакты, downloads, exfil                     |
| filesystem-agent | MFT, USN journal                         | Файловая активность, timestomping                 |
| network-agent    | PCAP, netflow, firewall logs             | C2, lateral, exfil                                |
| threatintel-agent| LLM-wiki                                 | Сопоставление с TTPs/IOCs из отчётов              |

Координация: orchestrator-агент распределяет подзадачи, собирает результаты от сабагентов, формирует общий отчёт.

## Ограничения и безопасность

- Агент не модифицирует evidence и не запускает plaso - только читает RAG
- Все ответы логируются с входным промптом и hit-list для аудита
- Агент помечает low-confidence ответы как "требует проверки аналитиком"
- Rate-limit на LLM-вызовы чтобы не разрастался cost