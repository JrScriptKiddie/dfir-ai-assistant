# DFIR Agent Skills

Skills - домен-специфичные паттерны ретривала и анализа для DFIR-агента.

## Концепция

Каждый skill определяет:
- **queries**: семантические запросы к RAG (TF-IDF vector search)
- **filters**: фильтры по metadata (source=EVTX/REG, event_id)
- **keywords**: точные подстроки для keyword search
- **follow_up**: вопросы для анализа после ретривала
- **report_sections**: секции отчёта, которые skill помогает заполнить
- **priority**: 1=высокий, 10=низкий

Агент использует hybrid retrieval: semantic (TF-IDF) + keyword (substring match).
Это позволяет находить и семантически похожие события, и точные IOC
(имена файлов, IP-адреса, service names).

## Incident Mode Skills

| Skill | Event IDs | Keywords | Что ищет |
|-------|-----------|----------|----------|
| service_abuse | 7045 | service, install, %systemroot%, LocalSystem | Вредоносные сервисы, рандомизированные имена |
| lateral_movement | 7045, 4624 | PSEXESVC, PsExec, Remote | PsExec, SMB, RDP lateral movement |
| ransomware | - | encrypted, readme, .td1738, install.exe | Шифрование, ransom notes, encryptor binary |
| impacket_smbexec | 7045 | BTOBTO, execute.bat, __output, COMSPEC | Impacket smbexec.py pattern |
| recon | - | whoami, ipconfig, netstat, tasklist, ping, dir | Reconnaissance commands |
| logon_analysis | 4624, 4625 | Logon Type, Source Network Address, NTLM | Logon events, PtH, source IPs |
| amcache_execution | - | amcache, shimcache, UserAssist, sha | Executed binaries, hashes |
| mft_filesystem | - | install.exe, ProgramData, readme, MFT | File creation, malware drop, encryption |

## Assessment Mode Skills

Все incident skills + дополнительные:

| Skill | Что ищет |
|-------|----------|
| persistence | Run keys, scheduled tasks, autorun |
| user_activity | UserAssist, NTUSER, user activity, compromised accounts |
| network_indicators | Source IPs, ports, WinRM/RDP/SMB firewall rules |

## Hybrid Retrieval

```
Skill -> queries -> TF-IDF vector search -> hits
      -> keywords -> substring match -> hits
      -> event_ids -> post-filter / targeted keyword search -> hits
      -> merge & deduplicate by chunk.id
```

## Добавление нового skill

1. Создать Skill(...) в src/agents/skills.py
2. Добавить в INCIDENT_SKILLS или ASSESSMENT_SKILLS
3. Указать queries, keywords, event_ids, follow_up
4. Тест: убедиться что keyword_search находит нужные chunks

## Результаты на SRV.nebo.ru

С skills агент нашёл (vs без skills):
- Полную последовательность BTOBTO команд (whoami -> tasklist -> ping -> dir -> ipconfig -> netstat)
- Anonymous NTLM V1 logon (нет в эталонном отчёте)
- 11 MITRE ATT&CK TTPs (vs 4 без skills)
- Детальные IOCs: service names, paths, users, network indicators
- RISK LEVEL: CRITICAL с обоснованием