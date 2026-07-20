"""Plaso knowledge base - parser catalog and usage patterns.

Loaded from docs/plaso_parsers.json (parsed from `log2timeline --parsers list`).
Used by the agent to understand which parsers produce which artifacts,
and to recommend parser presets for specific DFIR scenarios.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ParserInfo:
    name: str
    description: str
    category: str = "parser"
    plugins: dict[str, str] = field(default_factory=dict)
    # DFIR relevance: what forensic questions this parser helps answer
    dfir_use_cases: list[str] = field(default_factory=list)
    # Which Windows artifacts / event sources this parser covers
    artifact_sources: list[str] = field(default_factory=list)
    # Recommended for which scenarios
    scenarios: list[str] = field(default_factory=list)


# DFIR-relevant parser metadata (manually curated for key parsers)
DFIR_PARSER_METADATA = {
    "winevtx": {
        "dfir_use_cases": [
            "Logon analysis (4624/4625 - user, source IP, logon type)",
            "Service installations (7045 - malware persistence via services)",
            "Process creation (4688 - command line if audit enabled)",
            "Scheduled task creation (4698)",
            "Account management (4720/4722/4724 - create/enable/password reset)",
            "Share access (5140/5145 - SMB share enumeration)",
            "Power events (6005/6006/6008 - boot/shutdown/unexpected shutdown)",
        ],
        "artifact_sources": ["Security.evtx", "System.evtx", "Application.evtx",
                             "Microsoft-Windows-TaskScheduler/Operational.evtx",
                             "Microsoft-Windows-PowerShell/Operational.evtx"],
        "scenarios": ["incident", "assessment", "lateral_movement", "persistence"],
    },
    "winreg": {
        "dfir_use_cases": [
            "Persistence: Run/RunOnce keys, Startup folder",
            "Amcache: executed binaries with SHA-1 hashes and timestamps",
            "ShimCache/AppCompatCache: programs that ran (execution history)",
            "UserAssist: GUI-launched programs per user (execution count + time)",
            "TypedPaths: URLs typed in Explorer",
            "AutoRuns: services, drivers, scheduled tasks in registry",
            "RDP settings: fDenyTSConnections, SavedAccounts",
            "Last logged on user",
        ],
        "artifact_sources": ["NTUSER.DAT", "SOFTWARE", "SYSTEM", "SAM", "SECURITY",
                             "Amcache.hve", "DEFAULT"],
        "scenarios": ["incident", "assessment", "persistence", "execution_history"],
    },
    "prefetch": {
        "dfir_use_cases": [
            "Program execution history (first/last run, run count)",
            "Files loaded by executable (DLLs, data files)",
            "Volume from which program was run",
            "Identify malware execution even if binary is deleted",
        ],
        "artifact_sources": ["C:\\Windows\\Prefetch\\*.pf"],
        "scenarios": ["incident", "execution_history", "malware_identification"],
    },
    "mft": {
        "dfir_use_cases": [
            "File creation/modification/accessed timestamps (MACB)",
            "Identify when malware was dropped to disk",
            "Track ransomware file modification patterns (mass rename/encrypt)",
            "File deletion records (still in MFT if not overwritten)",
            "Alternate Data Streams (ADS) - hidden data",
        ],
        "artifact_sources": ["$MFT"],
        "scenarios": ["incident", "ransomware", "malware_drop", "file_timeline"],
    },
    "usnjrnl": {
        "dfir_use_cases": [
            "File system change journal - all file/directory changes",
            "Track file creation, deletion, rename, modification",
            "Correlate with MFT for complete file activity picture",
            "Identify ransomware mass file modification window",
        ],
        "artifact_sources": ["$UsnJrnl:$J"],
        "scenarios": ["ransomware", "file_timeline", "anti_forensics_detection"],
    },
    "lnk": {
        "dfir_use_cases": [
            "Shortcut file analysis - recently opened files",
            "Track attacker's file access via LNK artifacts",
            "Identify files on removable media (USB history)",
            "Machine ID and volume serial numbers for tracking",
        ],
        "artifact_sources": ["*.lnk", "Recent\\*.lnk", "Desktop\\*.lnk"],
        "scenarios": ["user_activity", "lateral_movement", "data_exfil"],
    },
    "esedb": {
        "dfir_use_cases": [
            "SRUM: system resource usage (network, CPU, per-process)",
            "WebCacheV01.dat: IE/Edge browsing history",
            "File History: backup history",
            "User Access Logging: per-user access patterns",
        ],
        "artifact_sources": ["Windows.edb", "WebCacheV01.dat", "SRUDB.dat"],
        "scenarios": ["user_activity", "network_activity", "assessment"],
    },
    "sqlite": {
        "dfir_use_cases": [
            "Chrome/Edge/Firefox browsing history, downloads, cookies",
            "Skype/Teams communication logs",
            "TeraTerm/other app SQLite databases",
        ],
        "artifact_sources": ["History.db (Chrome)", "places.sqlite (Firefox)",
                             "cookies.db", "Extensions database"],
        "scenarios": ["user_activity", "c2_communication", "data_exfil"],
    },
    "recycle_bin": {
        "dfir_use_cases": [
            "Files deleted by user - original path, deletion time, size",
            "Recover deleted malware binaries from Recycle Bin",
            "Track attacker cleanup activity (deleting tools after use)",
        ],
        "artifact_sources": ["$Recycle.Bin\\$I*", "$Recycler\\INFO2"],
        "scenarios": ["anti_forensics", "malware_recovery"],
    },
    "winjob": {
        "dfir_use_cases": [
            "Scheduled task configuration - command, trigger, credentials",
            "Persistence via scheduled tasks (common malware technique)",
            "Task execution history",
        ],
        "artifact_sources": ["C:\\Windows\\Tasks\\*.job", "Tasks folder"],
        "scenarios": ["persistence", "scheduled_task_analysis"],
    },
    "pe": {
        "dfir_use_cases": [
            "PE header compilation timestamp (malware build time)",
            "Import/Export tables (capabilities assessment)",
            "PE imphash for malware family identification",
        ],
        "artifact_sources": ["*.exe", "*.dll", "*.sys"],
        "scenarios": ["malware_identification"],
    },
    "filestat": {
        "dfir_use_cases": [
            "Basic file metadata for non-MFT sources",
            "File hash computation for IOC matching",
        ],
        "artifact_sources": ["all files in triage"],
        "scenarios": ["assessment", "ioc_matching"],
    },
    "windefender_history": {
        "dfir_use_cases": [
            "Defender detection history - what was caught and when",
            "Malware that was quarantined or cleaned",
            "Detect attacker tools flagged by AV",
        ],
        "artifact_sources": ["DetectionHistory files"],
        "scenarios": ["malware_identification", "detection_history"],
    },
}


# Parser presets for specific DFIR scenarios
PARSER_PRESETS = {
    "windows_full": "winevtx,winreg,prefetch,mft,usnjrnl,lnk,esedb,sqlite,recycle_bin,winjob,pe,filestat",
    "windows_triage": "winevtx,winreg,prefetch,esedb,filestat",
    "ransomware": "winevtx,winreg,mft,usnjrnl,prefetch,recycle_bin,pe,filestat",
    "lateral_movement": "winevtx,winreg,prefetch,lnk,esedb,filestat",
    "persistence": "winevtx,winreg,winjob,prefetch,filestat",
    "user_activity": "winreg,sqlite,lnk,esedb,prefetch,winevtx,filestat",
    "minimal": "winevtx,winreg,filestat",
}


class PlasoKnowledgeBase:
    """Knowledge base of plaso parsers and their DFIR use cases."""

    def __init__(self) -> None:
        self._parsers: dict[str, ParserInfo] = {}
        self._load()

    def _load(self) -> None:
        # Load raw parser list
        json_path = PROJECT_ROOT / "docs" / "plaso_parsers.json"
        if json_path.exists():
            raw = json.loads(json_path.read_text(encoding="utf-8"))
            for name, info in raw.items():
                dfir_meta = DFIR_PARSER_METADATA.get(name, {})
                self._parsers[name] = ParserInfo(
                    name=name,
                    description=info.get("description", ""),
                    category=info.get("category", "parser"),
                    plugins=info.get("plugins", {}),
                    dfir_use_cases=dfir_meta.get("dfir_use_cases", []),
                    artifact_sources=dfir_meta.get("artifact_sources", []),
                    scenarios=dfir_meta.get("scenarios", []),
                )

    def get_parser(self, name: str) -> ParserInfo | None:
        return self._parsers.get(name)

    def parsers_for_scenario(self, scenario: str) -> list[ParserInfo]:
        """Return parsers relevant for a DFIR scenario."""
        return [
            p for p in self._parsers.values()
            if scenario in p.scenarios
        ]

    def get_preset(self, scenario: str) -> str:
        """Get parser preset string for log2timeline --parsers flag."""
        return PARSER_PRESETS.get(scenario, PARSER_PRESETS["windows_triage"])

    def find_parsers_for_artifact(self, artifact: str) -> list[ParserInfo]:
        """Find parsers that handle a specific artifact (e.g. 'evtx', 'NTUSER')."""
        artifact_lower = artifact.lower()
        results = []
        for p in self._parsers.values():
            for src in p.artifact_sources:
                if artifact_lower in src.lower():
                    results.append(p)
                    break
            if artifact_lower in p.description.lower():
                results.append(p)
        return results

    def format_for_llm(self, scenario: str | None = None) -> str:
        """Format parser knowledge as text for LLM context."""
        lines = ["PLASO PARSER KNOWLEDGE BASE:"]
        if scenario:
            preset = self.get_preset(scenario)
            lines.append(f"Recommended preset for '{scenario}': {preset}")
            parsers = self.parsers_for_scenario(scenario)
            lines.append(f"Parsers for this scenario ({len(parsers)}):")
            for p in parsers:
                lines.append(f"  {p.name}: {p.description}")
                for uc in p.dfir_use_cases[:3]:
                    lines.append(f"    - {uc}")
        else:
            lines.append("All DFIR-relevant parsers:")
            for name, meta in DFIR_PARSER_METADATA.items():
                p = self._parsers.get(name)
                desc = p.description if p else "N/A"
                lines.append(f"  {name}: {desc}")
                for uc in meta.get("dfir_use_cases", [])[:2]:
                    lines.append(f"    - {uc}")
        return "\n".join(lines)

    def all_parser_names(self) -> list[str]:
        return sorted(self._parsers.keys())