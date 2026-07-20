# Плейбуки реагирования

Структурированные сценарии реагирования по типам инцидентов. Агент использует их как шаблон для отчёта и как источник запросов к RAG.

## Формат

YAML:

```yaml
name: Ransomware investigation
trigger:
  - keywords: [ransomware, encrypt, .locked, note.txt]
  - event_patterns:
    - sourcetype: Security
      event_id: 4624
      logon_type: 3
      after_hours: true
steps:
  - name: Identify entry point
    rag_queries:
      - "user login unusual time"
      - "email attachment download"
    sources: [EVTX, browser, prefetch]
  - name: Map execution
    rag_queries:
      - "process create powershell cmd"
      - "rundll32 suspicious dll"
    sources: [prefetch, shimcache, EVTX]
  - name: Lateral movement
    rag_queries: [...]
  - name: Persistence
    rag_queries: [...]
  - name: Exfil / impact
    rag_queries: [...]
report_sections:
  - timeline
  - patient_zero
  - lateral_hosts
  - persistence_mechanisms
  - data_impact
  - iocs
  - recommendations
```

## Запланированные плейбуки

- ransomware.yml
- lateral_movement.yml
- initial_access.yml
- persistence_hunt.yml
- exfiltration.yml
- credential_theft.yml
- webshell.yml