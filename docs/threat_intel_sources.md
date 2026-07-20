# Источники threat-intel отчётов для LLM-wiki

## Вендорские блог-посты и отчёты

- Mandiant / Google Cloud Threat Intelligence
- CrowdStrike (adversary reports, blog)
- Microsoft Threat Intelligence (MSFT Threat Analysis Center)
- ESET (WeLiveSecurity)
- Kaspersky (Securelist)
- Trend Micro (research blogs)
- Cisco Talos
- Palo Alto Unit 42
- Sophos X-Ops
- SentinelOne (Labs)
- Symantec / Broadcom
- Check Point Research
- F-Secure / WithSecure
- Recorded Future (Insikt)
- IBM X-Force
- Mandiant Advantage blog

## Специализированные отчёты

- CISA advisories и AA-отчёты (aa24-xxx-a)
- FBI FLASH reports (публичные)
- NCSC / UK Gov threat reports
- ENISA threat landscape
- MITRE ATT&CK Evaluations (отчёты по эвалюациям)
- Red Canary Year in Review
- SANS ISC / Stormcast writeups

## Red-team / purple-team writeups

- Pwn dfir writeups
- Red Team blog (redteamer.es)
- RedXOR / RedGhost writeups
- Vysec / Outflank blog
-_elastic Security Labs

## Сообщество и агрегаторы

- The DFIR Report (ключевой источник - реальные инциденты end-to-end)
- CIRCL / MISP public feeds (для IOCs)
- AlienVault OTX
- Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- VirusTotal blog (intelligence reports)
- vx-underground

## Рекомендации по кураторству

1. Приоритет - end-to-end DFIR-отчёты (The DFIR Report, Mandiant), они ближе всего к нашим кейсам
2. Для каждого отчёта сохраняем оригинал (PDF/HTML) + распарсенный JSON
3. Указываем лицензию/правила использования в `wiki/reports/<report_id>/LICENSE.txt`
4. IOCs хранятся отдельно от нарратива для удобной выгрузки в STIX/OpenIOC
5. TTPs нормализуем через MITRE ATT&CK ID
6. Язык оригинала сохраняем, при необходимости - параллельный перевод в отдельном поле

## Правовая заметка

Перед массовой загрузкой проверить условия использования каждого источника. Большинство вендоров разрешают персональное/исследовательское использование с атрибуцией. Перепубликация полного текста - обычно нет, поэтому wiki хранит извлечённые факты (TTP/IOC) + краткое саммари своими словами, а не копию статьи.