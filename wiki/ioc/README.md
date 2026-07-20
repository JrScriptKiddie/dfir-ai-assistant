# IOC - каталоги индикаторов компрометации

Структура по типам:

- `ioc/hashes/` - sha256, sha1, md5
- `ioc/ipv4/` - IP-адреса
- `ioc/domains/` - домены
- `ioc/urls/` - URL
- `ioc/registry/` - registry keys / values
- `ioc/mutex/` - mutexes
- `ioc/yara/` - YARA-правила

Каждый IOC-файл - JSONL: `{"value": ..., "type": ..., "source_report": ..., "tags": [...], "first_seen": ..., "last_seen": ...}`

## Согласование с RAG

IOCs из wiki-статей автоматически выгружаются сюда при ingest.