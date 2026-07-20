"""Agent skills - domain-specific retrieval and analysis patterns.

Each skill defines:
  - name: identifier
  - description: what it does
  - queries: list of RAG queries to run
  - filters: metadata filters (source, event_id, etc.)
  - keywords: exact-match keywords to search in chunk text
  - follow_up: questions the agent should ask after initial retrieval
  - report_sections: sections to populate in the report
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Skill:
    """A DFIR analysis skill with retrieval strategy and reporting hints."""

    name: str
    description: str
    queries: list[str] = field(default_factory=list)
    filters: dict = field(default_factory=dict)
    keywords: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    follow_up: list[str] = field(default_factory=list)
    report_sections: list[str] = field(default_factory=list)
    priority: int = 5  # 1=high, 10=low


# ============================================================================
# INCIDENT MODE SKILLS
# ============================================================================

SERVICE_ABUSE = Skill(
    name="service_abuse",
    description="Detect malicious service installations (Event ID 7045), "
                "randomized service names, suspicious binary paths",
    queries=[
        "service install create new service",
        "service binary path systemroot executable",
        "random service name suspicious",
    ],
    filters={"source": "EVTX"},
    event_ids=["7045"],
    keywords=["service", "install", "%systemroot%", "LocalSystem"],
    follow_up=[
        "What service names look randomized (4-6 chars, no spaces)?",
        "What binary paths point to %systemroot% with random exe names?",
        "Are there services created outside normal maintenance windows?",
    ],
    report_sections=["FINDINGS", "IOCs", "TTPS"],
    priority=1,
)

LATERAL_MOVEMENT = Skill(
    name="lateral_movement",
    description="Detect PsExec, SMB, WMI, RDP lateral movement indicators",
    queries=[
        "PsExec remote execution service",
        "PSEXESVC service installation",
        "SMB admin share C$ access",
        "remote desktop RDP connection",
    ],
    filters={"source": "EVTX"},
    event_ids=["7045", "4624"],
    keywords=["PSEXESVC", "psexecsvc", "PsExec", "Remote"],
    follow_up=[
        "Which source IPs initiated network logons (type 3)?",
        "Which source IPs initiated RDP sessions (type 10)?",
        "Was PsExec used from SysInternals or Impacket?",
        "What credentials were used for lateral movement?",
    ],
    report_sections=["TIMELINE", "FINDINGS", "TTPS", "IOCs"],
    priority=1,
)

RANSOMWARE = Skill(
    name="ransomware",
    description="Detect ransomware execution, file encryption, ransom notes",
    queries=[
        "file encryption ransomware encrypted",
        "ransom note readme txt",
        "mass file modification creation",
        "encrypted file extension",
    ],
    keywords=["encrypted", "readme", "ransom", ".td1738", "install.exe",
              "ProgramData", "шифров", "зашифрован"],
    follow_up=[
        "What executable was dropped before encryption started?",
        "What file extension was added to encrypted files?",
        "When did mass file modifications begin and end?",
        "Was a ransom note created? What is its name?",
        "Which user account launched the encryptor?",
    ],
    report_sections=["TIMELINE", "FINDINGS", "IOCs"],
    priority=1,
)

IMPACKET_SMBEXEC = Skill(
    name="impacket_smbexec",
    description="Detect Impacket smbexec.py activity (BTOBTO pattern, "
                "%COMSPEC% batch execution, __output redirection)",
    queries=[
        "batch file execute command comspec",
        "BTOBTO service temporary batch",
        "output redirection C$ __output",
    ],
    filters={"source": "EVTX"},
    event_ids=["7045"],
    keywords=["BTOBTO", "execute.bat", "__output", "COMSPEC", "%TEMP%",
              "echo", "ipconfig", "netstat", "tasklist", "whoami"],
    follow_up=[
        "What commands were executed via batch files?",
        "Was output redirected to \\\\127.0.0.1\\C$\\__output?",
        "What reconnaissance commands were run (whoami, ipconfig, netstat, tasklist, dir)?",
        "Which user credentials were used for smbexec activity?",
    ],
    report_sections=["TIMELINE", "FINDINGS", "TTPS", "IOCs"],
    priority=1,
)

RECON = Skill(
    name="reconnaissance",
    description="Detect reconnaissance commands: whoami, ipconfig, netstat, "
                "tasklist, ping, dir, systeminfo",
    queries=[
        "reconnaissance command whoami ipconfig netstat",
        "tasklist process enumeration",
        "ping network connectivity check",
        "dir directory listing filesystem",
    ],
    keywords=["whoami", "ipconfig", "netstat", "tasklist", "ping",
              "dir c:", "systeminfo", "echo"],
    follow_up=[
        "What was the first reconnaissance command?",
        "Did the attacker check for security software (tasklist)?",
        "Did the attacker check internet connectivity (ping)?",
        "What directories were enumerated?",
    ],
    report_sections=["TIMELINE", "TTPS"],
    priority=2,
)

# ============================================================================
# ASSESSMENT MODE SKILLS (broader)
# ============================================================================

PERSISTENCE = Skill(
    name="persistence",
    description="Detect persistence mechanisms: services, Run keys, "
                "scheduled tasks, autorun",
    queries=[
        "autorun persistence run key registry startup",
        "scheduled task create registry entry",
        "service install persistence",
    ],
    filters={"source": "REG"},
    keywords=["Run", "Startup", "CurrentVersion", "Services", "ScheduledTasks"],
    follow_up=[
        "What Run keys were created or modified?",
        "Were any scheduled tasks created?",
        "What services were installed with suspicious binaries?",
    ],
    report_sections=["ANOMALIES", "FINDINGS", "TTPS"],
    priority=2,
)

LOGON_ANALYSIS = Skill(
    name="logon_analysis",
    description="Analyze logon events: type 3 (network), type 10 (RDP), "
                "failed logons, Pass-the-Hash indicators",
    queries=[
        "logon authentication user login type 3 network",
        "RDP remote desktop logon type 10",
        "failed logon denied access brute force",
        "NTLM authentication pass the hash",
    ],
    filters={"source": "EVTX"},
    event_ids=["4624", "4625"],
    keywords=["Logon Type", "Source Network Address", "NTLM", "Kerberos",
              "172.16", "adv_pavel", "kirill", "Administrator"],
    follow_up=[
        "What source IPs initiated logons?",
        "Which users had network logons (type 3)?",
        "Which users had RDP sessions (type 10)?",
        "Were there failed logon attempts (brute force)?",
        "Was NTLM used instead of Kerberos (PtH indicator)?",
    ],
    report_sections=["TIMELINE", "FINDINGS", "IOCs", "TTPS"],
    priority=1,
)

AMCACHE_EXECUTION = Skill(
    name="amcache_execution",
    description="Analyze Amcache/Shimcache for executed binaries, "
                "hashes, execution timestamps",
    queries=[
        "amcache executable program sha hash",
        "shimcache appcompat cache executed program",
        "userassist recently used application execution",
    ],
    filters={"source": "REG"},
    keywords=["amcache", "Amcache", "shimcache", "ShimCache", "AppCompat",
              "UserAssist", "program", "executable", "sha"],
    follow_up=[
        "What suspicious executables were run (randomized names)?",
        "What SHA hashes are recorded in Amcache?",
        "When was the ransomware binary first executed?",
        "What programs were run via GUI (UserAssist)?",
    ],
    report_sections=["FINDINGS", "IOCs"],
    priority=2,
)

MFT_FILESYSTEM = Skill(
    name="mft_filesystem",
    description="Analyze MFT for file creation, modification, deletion "
                "patterns indicating malware drop or encryption",
    queries=[
        "file creation modification recent MFT",
        "executable dll sys new file dropped",
        "ProgramData temp directory download file",
        "ransom note readme encrypted extension",
    ],
    keywords=["install.exe", "ProgramData", "readme", ".td1738",
              "encrypted", "ransom", "MFT", "file creation"],
    follow_up=[
        "When was the ransomware binary dropped to disk?",
        "What files appeared immediately before encryption?",
        "What file extensions were added during encryption?",
        "When did mass file modifications start and end?",
    ],
    report_sections=["TIMELINE", "FINDINGS", "IOCs"],
    priority=2,
)

USER_ACTIVITY = Skill(
    name="user_activity",
    description="Analyze UserAssist and registry for user activity, "
                "identify compromised accounts",
    queries=[
        "userassist application execution user activity",
        "user profile registry NTUSER recently used",
    ],
    filters={"source": "REG"},
    keywords=["UserAssist", "NTUSER", "ivan", "kirill", "adm_pavel",
              "Administrator", "notepad", "chrome", "install"],
    follow_up=[
        "Which users were active during the incident window?",
        "What programs were launched via GUI?",
        "Was the ransomware launched via GUI (UserAssist)?",
        "Which user accounts may be compromised?",
    ],
    report_sections=["FINDINGS", "IOCs"],
    priority=3,
)

NETWORK_INDICATORS = Skill(
    name="network_indicators",
    description="Extract network indicators: source IPs, ports, "
                "connections from logon events and firewall logs",
    queries=[
        "network connection source IP address",
        "firewall rule port open WinRM RDP SMB",
    ],
    event_ids=["4624", "4625"],
    keywords=["172.16", "192.168", "10.0", "Source Network Address",
              "5985", "3389", "445", "WinRM", "RDP"],
    follow_up=[
        "What internal IPs initiated connections to this host?",
        "What remote access services are enabled (WinRM, RDP, SMB)?",
        "Can we correlate source IPs with specific user sessions?",
    ],
    report_sections=["IOCs", "FINDINGS"],
    priority=2,
)

PLASO_KNOWLEDGE = Skill(
    name="plaso_knowledge",
    description="Apply plaso parser knowledge to interpret artifacts: "
                "understand which parser produced each event, what it means "
                "forensically, and what questions it can answer",
    queries=[
        "parser winevtx event log security system application",
        "parser winreg registry amcache shimcache userassist",
        "parser prefetch execution history program",
        "parser mft file system modification creation",
    ],
    keywords=["winevtx", "winreg", "prefetch", "mft", "usnjrnl",
              "amcache", "shimcache", "AppCompatCache", "UserAssist",
              "filestat", "esedb", "srum", "lnk"],
    follow_up=[
        "Which plaso parsers produced the events in the RAG hits?",
        "What forensic questions can each parser's data answer?",
        "Are there parser types missing from the triage that would help?",
        "For EVTX events: which event IDs are present and what do they indicate?",
        "For registry events: which hive (NTUSER/SOFTWARE/SYSTEM) and what keys?",
    ],
    report_sections=["FINDINGS", "RECOMMENDATIONS"],
    priority=3,
)


# ============================================================================
# SKILL COLLECTIONS
# ============================================================================

INCIDENT_SKILLS = [
    SERVICE_ABUSE,
    LATERAL_MOVEMENT,
    RANSOMWARE,
    IMPACKET_SMBEXEC,
    RECON,
    LOGON_ANALYSIS,
    AMCACHE_EXECUTION,
    MFT_FILESYSTEM,
    PLASO_KNOWLEDGE,
]

ASSESSMENT_SKILLS = [
    LOGON_ANALYSIS,
    SERVICE_ABUSE,
    LATERAL_MOVEMENT,
    PERSISTENCE,
    IMPACKET_SMBEXEC,
    RANSOMWARE,
    RECON,
    AMCACHE_EXECUTION,
    MFT_FILESYSTEM,
    USER_ACTIVITY,
    NETWORK_INDICATORS,
    PLASO_KNOWLEDGE,
]

ALL_SKILLS = {
    s.name: s for s in INCIDENT_SKILLS + ASSESSMENT_SKILLS
}