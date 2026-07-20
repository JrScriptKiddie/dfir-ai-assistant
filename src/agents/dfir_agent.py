"""General DFIR Agent with skill-based retrieval.

Two modes:
  - "incident": analyst provides incident description, agent investigates
    using skills + RAG hits relevant to the description
  - "assessment": agent explores the triage autonomously using all skills,
    finds anomalies, produces a compromise assessment summary

Both modes use hybrid retrieval:
  1. Semantic: TF-IDF vector search for each skill's queries
  2. Keyword: exact substring match for skill-specific keywords
  3. Merge and deduplicate hits
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..rag.embedder import Embedder, get_embedder
from ..rag.turbovec import Hit, TurboVec
from .llm import LLMProvider, get_llm
from .plaso_knowledge import PlasoKnowledgeBase
from .skills import Skill, INCIDENT_SKILLS, ASSESSMENT_SKILLS

# ---- prompts ----

SYSTEM_PROMPT_INCIDENT = """\
You are a DFIR (Digital Forensics & Incident Response) analyst working \
with a supertimeline of a security incident stored in a RAG vector database.

You are given a known incident description from the analyst. Your job is to \
investigate the timeline using the provided RAG hits and produce a report.

RULES:
1. Every factual statement MUST reference a source chunk.id from the RAG hits.
2. Statements without a source are HYPOTHESES and must be labeled as such.
3. Use the provided RAG hits as your primary evidence. Do not invent events.
4. Structure your report in these sections:
   - SUMMARY: brief overview of what happened
   - TIMELINE: key events in chronological order (with chunk.id refs)
   - FINDINGS: confirmed facts (with chunk.id refs)
   - HYPOTHESES: unconfirmed theories (explicitly labeled)
   - TTPS: relevant MITRE ATT&CK techniques if identifiable
   - IOCs: indicators of compromise found in the data
   - RECOMMENDATIONS: next steps for the analyst
   - OPEN QUESTIONS: what needs further investigation
5. Be concise. Cite chunk.id in square brackets like [abc123def4567890].
6. If RAG hits are insufficient, say so in OPEN QUESTIONS.
7. When you identify source IPs, user accounts, file paths, or service names, \
list them explicitly in IOCs.
8. Try to establish: WHO (which user/account), WHEN (exact timestamps), \
HOW (what tool/method was used for each action).
9. If you see evidence of Impacket (smbexec.py, psexec.py) or SysInternals PsExec, \
distinguish between them - they have different service patterns.
10. If you see reconnaissance commands (whoami, ipconfig, netstat, tasklist, \
ping, dir), list them in order - they reveal attacker's objectives.
"""

SYSTEM_PROMPT_ASSESSMENT = """\
You are a DFIR (Digital Forensics & Incident Response) analyst performing \
a Compromise Assessment on a system. You have a supertimeline stored in a \
RAG vector database. No prior incident description is given - you must \
autonomously explore the data using the provided RAG hits, identify anomalies, \
suspicious activity, and potential compromise, then produce an assessment.

RULES:
1. Every factual statement MUST reference a source chunk.id from the RAG hits.
2. Statements without a source are HYPOTHESES and must be labeled as such.
3. Use the provided RAG hits as your primary evidence. Do not invent events.
4. Structure your assessment in these sections:
   - ASSESSMENT SUMMARY: overall verdict - is the system compromised?
   - ANOMALIES: suspicious events found (with chunk.id refs)
   - TIMELINE: chronological view of suspicious activity (with chunk.id refs)
   - FINDINGS: confirmed facts (with chunk.id refs)
   - HYPOTHESES: what may have happened (explicitly labeled)
   - TTPS: relevant MITRE ATT&CK techniques if identifiable
   - IOCs: indicators of compromise (IPs, users, file paths, service names, hashes)
   - RISK LEVEL: Low / Medium / High / Critical with justification
   - RECOMMENDATIONS: next steps for the analyst
   - OPEN QUESTIONS: what needs further investigation
5. Be concise. Cite chunk.id in square brackets like [abc123def4567890].
6. If no anomalies are found, state the system appears clean but note \
limitations of the assessment.
7. Pay attention to: unusual service installations (Event ID 7045), suspicious \
process names (randomized, misspelled), unexpected network connections, \
persistence mechanisms, credential dumping, lateral movement tools \
(PsExec, Impacket smbexec), mass file modifications, out-of-hours activity.
8. When you find source IPs or user accounts in logon events, extract and \
report them as IOCs.
9. Distinguish between Impacket psexec/smbexec (randomized service names, \
BTOBTO pattern, %COMSPEC% batch) and SysInternals PsExec (PSEXESVC service).
10. Look for reconnaissance command sequences (whoami, ipconfig, netstat, \
tasklist, ping, dir) - they indicate attacker objectives.
11. Try to establish the full attack chain: initial access -> execution -> \
persistence -> recon -> lateral movement -> impact (encryption).
"""

USER_TEMPLATE_INCIDENT = """\
INCIDENT DESCRIPTION:
{description}

SKILLS APPLIED:
{skills_summary}

RAG HITS (events from the case timeline, retrieved via semantic + keyword search):
{hits}

FOLLOW-UP QUESTIONS FOR YOUR ANALYSIS:
{follow_ups}

{plaso_context}

Analyze the incident using the above evidence. Follow the report structure. \
Establish WHO, WHEN, and HOW for each significant action. \
Use the plaso parser knowledge to interpret which artifacts produced each event \
and what forensic questions they answer.
"""

USER_TEMPLATE_ASSESSMENT = """\
COMPROMISE ASSESSMENT - no incident description provided.

The analyst has asked you to assess whether this system is compromised.

SKILLS APPLIED:
{skills_summary}

RAG HITS (events from the case timeline, covering multiple event types \
and time ranges, retrieved via semantic + keyword search):
{hits}

FOLLOW-UP QUESTIONS FOR YOUR ANALYSIS:
{follow_ups}

{plaso_context}

Analyze the evidence and produce a compromise assessment. \
Follow the assessment structure. Focus on anomalies, attack chain, and IOCs. \
Try to establish the full sequence: initial access -> execution -> persistence \
-> recon -> lateral movement -> impact. \
Use the plaso parser knowledge to interpret which artifacts produced each event \
and what forensic questions they answer.
"""


@dataclass
class AgentResult:
    report: str
    hits_used: list[Hit] = field(default_factory=list)
    queries_made: list[str] = field(default_factory=list)
    skills_used: list[str] = field(default_factory=list)
    mode: str = "incident"


class DFIRAgent:
    """DFIR agent with skill-based hybrid retrieval.

    Modes:
        - "incident": guided investigation with known incident description
        - "assessment": autonomous compromise assessment (no description)
    """

    def __init__(
        self,
        store: TurboVec,
        embedder: Embedder | None = None,
        llm: LLMProvider | None = None,
        k: int = 20,
    ) -> None:
        self.store = store
        self.embedder = embedder or get_embedder()
        self.llm = llm or get_llm()
        self.k = k
        self.plaso_kb = PlasoKnowledgeBase()

    def _detect_incident_window(self, hits: list[Hit]) -> tuple[str, str] | None:
        """Detect the incident time window from suspicious hits.

        Looks for the tightest cluster of high-scoring suspicious events.
        Returns (start, end) ISO timestamps or None if no window found.
        """
        # Collect timestamps from hits with suspicious indicators
        suspicious_times: list[str] = []
        suspicious_keywords = [
            "7045", "BTOBTO", "PSEXESVC", "HYlugq", "pnLXsIao",
            "encrypted", "install.exe", "McBz", "Sauh",
            "4624", "lateral", "service install",
        ]
        for h in hits:
            text_lower = h.chunk.text.lower()
            if any(kw.lower() in text_lower for kw in suspicious_keywords):
                ts = h.chunk.metadata.get("timestamp", "")
                if ts:
                    suspicious_times.append(ts)
        if len(suspicious_times) < 2:
            return None
        suspicious_times.sort()
        # Find the tightest cluster: group events within 2 hours of each other
        best_cluster = [suspicious_times[0]]
        current_cluster = [suspicious_times[0]]
        for i in range(1, len(suspicious_times)):
            # if within 2 hours of previous, add to current cluster
            if _time_diff_hours(suspicious_times[i-1], suspicious_times[i]) < 2:
                current_cluster.append(suspicious_times[i])
            else:
                if len(current_cluster) > len(best_cluster):
                    best_cluster = list(current_cluster)
                current_cluster = [suspicious_times[i]]
        if len(current_cluster) > len(best_cluster):
            best_cluster = list(current_cluster)
        if len(best_cluster) < 2:
            return None
        # expand window by 30 min on each side
        start = _shift_time(best_cluster[0], -1800)  # -30 min
        end = _shift_time(best_cluster[-1], 1800)  # +30 min
        return start, end

    def _retrieve_with_skill(
        self, skill: Skill, time_window: tuple[str, str] | None = None
    ) -> list[Hit]:
        """Hybrid retrieval for one skill: semantic + keyword.

        If time_window is provided, applies time_range filter to narrow hits.
        """
        hits: dict[str, Hit] = {}

        # build filters: combine skill filters with time window
        filters = dict(skill.filters) if skill.filters else {}
        if time_window:
            filters["time_range"] = {"start": time_window[0], "end": time_window[1]}

        # 1. semantic retrieval (TF-IDF vector search)
        for q in skill.queries:
            q_vec = self.embedder.embed([q])[0]
            for h in self.store.query(q_vec, k=self.k, filters=filters or None):
                if h.chunk.id not in hits or h.score > hits[h.chunk.id].score:
                    hits[h.chunk.id] = h

        # 2. keyword retrieval (exact substring match)
        if skill.keywords:
            kw_hits = self.store.keyword_search(
                skill.keywords, k=self.k, filters=filters or None
            )
            for h in kw_hits:
                if h.chunk.id not in hits:
                    hits[h.chunk.id] = h

        # 3. event_id filter (post-retrieval)
        if skill.event_ids:
            filtered = {
                cid: h
                for cid, h in hits.items()
                if h.chunk.metadata.get("event_id", "") in skill.event_ids
            }
            # also do keyword search specifically for event IDs
            for eid in skill.event_ids:
                eid_hits = self.store.keyword_search(
                    [f"[{eid} /"], k=self.k, filters=filters or None
                )
                for h in eid_hits:
                    if h.chunk.id not in filtered:
                        filtered[h.chunk.id] = h
            hits = filtered

        return sorted(hits.values(), key=lambda h: -h.score)[: self.k]

    def _retrieve_incident(self, description: str) -> tuple[list[Hit], list[Skill]]:
        """Retrieve hits using incident-mode skills + description query.

        Two-phase retrieval:
        Phase 1: broad retrieval to detect incident time window
        Phase 2: time-sliced retrieval focused on incident window
        """
        skills = INCIDENT_SKILLS
        phase1_hits: dict[str, Hit] = {}

        # broad query with the description itself
        q_vec = self.embedder.embed([description])[0]
        for h in self.store.query(q_vec, k=self.k):
            phase1_hits[h.chunk.id] = h

        # Phase 1: skill-based retrieval without time filter
        for skill in skills:
            skill_hits = self._retrieve_with_skill(skill)
            for h in skill_hits:
                if h.chunk.id not in phase1_hits or h.score > phase1_hits[h.chunk.id].score:
                    phase1_hits[h.chunk.id] = h

        # also keyword search with description entities
        desc_keywords = _extract_keywords(description)
        if desc_keywords:
            for h in self.store.keyword_search(desc_keywords, k=self.k):
                if h.chunk.id not in phase1_hits:
                    phase1_hits[h.chunk.id] = h

        # Detect incident window from phase 1 hits
        phase1_list = sorted(phase1_hits.values(), key=lambda h: -h.score)
        time_window = self._detect_incident_window(phase1_list)

        if time_window:
            # Phase 2: re-run skills with time window filter for precision
            phase2_hits: dict[str, Hit] = dict(phase1_hits)
            for skill in skills:
                skill_hits = self._retrieve_with_skill(skill, time_window=time_window)
                for h in skill_hits:
                    if h.chunk.id not in phase2_hits:
                        phase2_hits[h.chunk.id] = h
            hits = sorted(phase2_hits.values(), key=lambda h: -h.score)
        else:
            hits = phase1_list

        return hits[: self.k * 3], skills

    def _retrieve_assessment(self) -> tuple[list[Hit], list[Skill]]:
        """Retrieve hits using assessment-mode skills (all skills).

        Two-phase: broad -> detect window -> time-sliced refinement.
        """
        skills = ASSESSMENT_SKILLS
        phase1_hits: dict[str, Hit] = {}

        for skill in skills:
            skill_hits = self._retrieve_with_skill(skill)
            for h in skill_hits:
                if h.chunk.id not in phase1_hits or h.score > phase1_hits[h.chunk.id].score:
                    phase1_hits[h.chunk.id] = h

        # Detect incident window
        phase1_list = sorted(phase1_hits.values(), key=lambda h: -h.score)
        time_window = self._detect_incident_window(phase1_list)

        if time_window:
            phase2_hits: dict[str, Hit] = dict(phase1_hits)
            for skill in skills:
                skill_hits = self._retrieve_with_skill(skill, time_window=time_window)
                for h in skill_hits:
                    if h.chunk.id not in phase2_hits:
                        phase2_hits[h.chunk.id] = h
            hits = sorted(phase2_hits.values(), key=lambda h: -h.score)
        else:
            hits = phase1_list

        return hits[: self.k * 3], skills

    def run_incident(self, description: str) -> AgentResult:
        """Run incident investigation mode."""
        hits, skills = self._retrieve_incident(description)
        skills_summary = "\n".join(
            f"  - {s.name}: {s.description}" for s in skills
        )
        follow_ups = "\n".join(
            f"  [{s.name}] {q}" for s in skills for q in s.follow_up[:2]
        )
        hits_text = "\n".join(
            f"[{h.chunk.id}] (score={h.score:.3f}) {h.chunk.text}" for h in hits
        )
        plaso_context = self.plaso_kb.format_for_llm("incident")
        user_msg = USER_TEMPLATE_INCIDENT.format(
            description=description,
            skills_summary=skills_summary,
            hits=hits_text,
            follow_ups=follow_ups,
            plaso_context=plaso_context,
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_INCIDENT},
            {"role": "user", "content": user_msg},
        ]
        report = self.llm.chat(messages, temperature=0.2)
        return AgentResult(
            report=report,
            hits_used=hits,
            queries_made=[description],
            skills_used=[s.name for s in skills],
            mode="incident",
        )

    def run_assessment(self) -> AgentResult:
        """Run autonomous compromise assessment mode."""
        hits, skills = self._retrieve_assessment()
        skills_summary = "\n".join(
            f"  - {s.name}: {s.description}" for s in skills
        )
        follow_ups = "\n".join(
            f"  [{s.name}] {q}" for s in skills for q in s.follow_up[:2]
        )
        hits_text = "\n".join(
            f"[{h.chunk.id}] (score={h.score:.3f}) {h.chunk.text}" for h in hits
        )
        plaso_context = self.plaso_kb.format_for_llm("assessment")
        user_msg = USER_TEMPLATE_ASSESSMENT.format(
            skills_summary=skills_summary,
            hits=hits_text,
            follow_ups=follow_ups,
            plaso_context=plaso_context,
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_ASSESSMENT},
            {"role": "user", "content": user_msg},
        ]
        report = self.llm.chat(messages, temperature=0.2)
        return AgentResult(
            report=report,
            hits_used=hits,
            queries_made=["assessment"],
            skills_used=[s.name for s in skills],
            mode="assessment",
        )

    def run(self, description: str | None = None) -> AgentResult:
        """Run agent. If description is None, runs assessment mode."""
        if description:
            return self.run_incident(description)
        return self.run_assessment()


def _extract_keywords(text: str) -> list[str]:
    """Extract potential keywords from incident description."""
    import re

    keywords: list[str] = []
    # IPs
    for m in re.finditer(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
        keywords.append(m.group())
    # executable names
    for m in re.finditer(r"\b\w+\.exe\b", text, re.IGNORECASE):
        keywords.append(m.group())
    # usernames (DOMAIN\user pattern)
    for m in re.finditer(r"\b(\w+)\\\w+", text):
        keywords.append(m.group())
    # service names
    for m in re.finditer(r"\b(service|McBz|Sauh|BTOBTO|PSEXESVC)\b", text, re.IGNORECASE):
        keywords.append(m.group())
    # capitalized tokens (hostnames, tools)
    for m in re.finditer(r"\b[A-Z][a-zA-Z0-9]{3,}\b", text):
        keywords.append(m.group())
    return keywords[:10]


def _time_diff_hours(t1: str, t2: str) -> float:
    """Approximate time difference in hours between two ISO timestamps."""
    from datetime import datetime

    try:
        d1 = datetime.fromisoformat(t1.replace("Z", "+00:00"))
        d2 = datetime.fromisoformat(t2.replace("Z", "+00:00"))
        return abs((d2 - d1).total_seconds()) / 3600
    except (ValueError, TypeError):
        # fallback: string comparison (works for ISO format)
        return 0.0 if t1 == t2 else 24.0


def _shift_time(ts: str, seconds: int) -> str:
    """Shift an ISO timestamp by +/- seconds."""
    from datetime import datetime, timedelta

    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        d = d + timedelta(seconds=seconds)
        return d.isoformat()
    except (ValueError, TypeError):
        return ts