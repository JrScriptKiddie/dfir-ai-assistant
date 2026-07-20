"""Tests for DFIR agent skills and hybrid retrieval."""

import numpy as np

from src.agents.dfir_agent import DFIRAgent
from src.agents.skills import (
    ALL_SKILLS,
    ASSESSMENT_SKILLS,
    INCIDENT_SKILLS,
)
from src.rag.embedder import DummyEmbedder
from src.rag.turbovec import Chunk, TurboVec


class MockLLM:
    """Mock LLM that returns a canned response with chunk.id references."""

    def __init__(self, response: str = "MOCK REPORT"):
        self._response = response
        self._model = "mock"

    @property
    def model(self) -> str:
        return self._model

    def chat(self, messages: list[dict], temperature: float = 0.2) -> str:
        import re

        user_msg = messages[-1]["content"]
        ids = re.findall(r"\[([a-f0-9]{1,20})\]", user_msg)
        if ids:
            return f"MOCK REPORT\nFINDINGS: found {len(ids)} hits\nFirst: [{ids[0]}]"
        return "MOCK REPORT\nNo hits found"


def _build_test_store() -> TurboVec:
    """Build a test store with realistic DFIR-like events."""
    store = TurboVec(dim=256, case_id="test")
    chunks = [
        Chunk(id="aaa1", text="2021-04-19 | EVTX | Security | 7045 | Service install McBz %systemroot%\\HYlugqMY.exe LocalSystem",
              metadata={"source": "EVTX", "event_id": "7045", "timestamp": "2021-04-19T07:39:33Z"}),
        Chunk(id="bbb2", text="2021-04-19 | EVTX | Security | 7045 | Service install Sauh %systemroot%\\pnLXsIao.exe LocalSystem",
              metadata={"source": "EVTX", "event_id": "7045", "timestamp": "2021-04-19T07:43:42Z"}),
        Chunk(id="ccc3", text="2021-04-19 | EVTX | Security | 7045 | BTOBTO service %COMSPEC% execute.bat __output ipconfig",
              metadata={"source": "EVTX", "event_id": "7045", "timestamp": "2021-04-19T07:54:21Z"}),
        Chunk(id="ddd4", text="2021-04-19 | EVTX | System | 7036 | PSEXESVC service started",
              metadata={"source": "EVTX", "event_id": "7036", "timestamp": "2021-04-19T08:03:43Z"}),
        Chunk(id="eee5", text="2021-04-19 | EVTX | Security | 4624 | Logon user NEBO\\adm_pavel type 3 172.16.2.22",
              metadata={"source": "EVTX", "event_id": "4624", "timestamp": "2021-04-19T07:39:32Z"}),
        Chunk(id="fff6", text="2021-04-19 | EVTX | Security | 4624 | Logon user NEBO\\kirill type 10 RDP 172.16.2.20",
              metadata={"source": "EVTX", "event_id": "4624", "timestamp": "2021-04-19T07:52:14Z"}),
        Chunk(id="ggg7", text="2021-04-19 | REG | UserAssist | user kirill install.exe ProgramData execution",
              metadata={"source": "REG", "timestamp": "2021-04-19T08:04:09Z"}),
        Chunk(id="hhh8", text="2020-01-01 | REG | Software | benign application install",
              metadata={"source": "REG", "timestamp": "2020-01-01T00:00:00Z"}),
    ]
    vecs = np.eye(8, 256, dtype=np.float32)
    store.add(chunks, vecs)
    return store


# ---- skill tests ----

def test_skills_have_names():
    """All skills in ALL_SKILLS dict have unique names."""
    assert len(ALL_SKILLS) >= 10
    # ALL_SKILLS is a dict keyed by name, so uniqueness is guaranteed
    for name, skill in ALL_SKILLS.items():
        assert skill.name == name


def test_assessment_has_more_skills():
    """Assessment mode should have at least as many skills as incident."""
    assert len(ASSESSMENT_SKILLS) >= len(INCIDENT_SKILLS)


def test_skill_has_queries_and_keywords():
    """Every skill should have at least one retrieval strategy."""
    for skill in ALL_SKILLS.values():
        assert len(skill.queries) > 0 or len(skill.keywords) > 0, \
            f"skill {skill.name} has no queries or keywords"


# ---- keyword search tests ----

def test_keyword_search_finds_iocs():
    """Keyword search should find specific IOC strings."""
    store = _build_test_store()
    hits = store.keyword_search(["HYlugqMY", "pnLXsIao", "BTOBTO"])
    ids = {h.chunk.id for h in hits}
    assert "aaa1" in ids  # HYlugqMY
    assert "bbb2" in ids  # pnLXsIao
    assert "ccc3" in ids  # BTOBTO


def test_keyword_search_case_insensitive():
    """Keyword search should be case-insensitive."""
    store = _build_test_store()
    hits = store.keyword_search(["psexesvc"])
    ids = {h.chunk.id for h in hits}
    assert "ddd4" in ids  # PSEXESVC


def test_keyword_search_with_filters():
    """Keyword search with source filter."""
    store = _build_test_store()
    hits = store.keyword_search(["install.exe"], filters={"source": "REG"})
    ids = {h.chunk.id for h in hits}
    assert "ggg7" in ids


# ---- agent tests ----

def test_incident_mode_finds_suspicious_services():
    """Incident mode with skills should find service abuse events."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=5)

    result = agent.run_incident("files encrypted, suspicious services installed")
    assert result.mode == "incident"
    hit_ids = {h.chunk.id for h in result.hits_used}
    # should find at least one of the suspicious service events via keyword search
    assert "aaa1" in hit_ids or "bbb2" in hit_ids or "ccc3" in hit_ids


def test_assessment_mode_finds_lateral_movement():
    """Assessment mode should find PsExec/lateral movement via skills."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=5)

    result = agent.run_assessment()
    assert result.mode == "assessment"
    hit_ids = {h.chunk.id for h in result.hits_used}
    # should find PSEXESVC via keyword search
    assert "ddd4" in hit_ids
    # should find logon events via skill
    assert "eee5" in hit_ids or "fff6" in hit_ids


def test_run_dispatches_by_description():
    """run() with description -> incident, without -> assessment."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=5)

    r1 = agent.run("ransomware encryption")
    assert r1.mode == "incident"
    assert len(r1.skills_used) > 0

    r2 = agent.run()
    assert r2.mode == "assessment"
    assert len(r2.skills_used) > 0


def test_skills_used_in_result():
    """AgentResult should list which skills were used."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=5)

    result = agent.run_assessment()
    assert "logon_analysis" in result.skills_used
    assert "service_abuse" in result.skills_used
    assert "lateral_movement" in result.skills_used


def test_time_window_detection():
    """Agent should detect incident time window from suspicious hits."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=10)

    # get phase 1 hits
    hits, _ = agent._retrieve_assessment()
    window = agent._detect_incident_window(hits)
    assert window is not None
    start, end = window
    # window should contain the 2021-04-19 events
    assert "2021-04-19" in start
    assert "2021-04-19" in end


def test_time_range_filter_in_keyword_search():
    """keyword_search with time_range filter should narrow results."""
    store = _build_test_store()
    # search for "service" in the incident window
    hits = store.keyword_search(
        ["service", "install"],
        k=10,
        filters={"time_range": {"start": "2021-04-19T00:00:00Z", "end": "2021-04-19T23:59:59Z"}},
    )
    # should find only 2021-04-19 events
    for h in hits:
        assert "2021-04-19" in h.chunk.metadata.get("timestamp", "")
    # should find the suspicious service events
    ids = {h.chunk.id for h in hits}
    assert "aaa1" in ids or "bbb2" in ids or "ccc3" in ids


def test_plaso_knowledge_in_agent():
    """Agent should have plaso knowledge base loaded."""
    store = _build_test_store()
    emb = DummyEmbedder(dim=256)
    llm = MockLLM()
    agent = DFIRAgent(store=store, embedder=emb, llm=llm, k=5)
    assert agent.plaso_kb is not None
    assert len(agent.plaso_kb.all_parser_names()) > 0
    # plaso_knowledge skill should be in assessment skills
    result = agent.run_assessment()
    assert "plaso_knowledge" in result.skills_used