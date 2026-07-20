"""Tests for plaso knowledge base."""

from src.agents.plaso_knowledge import PlasoKnowledgeBase, PARSER_PRESETS


def test_knowledge_base_loads():
    kb = PlasoKnowledgeBase()
    assert len(kb.all_parser_names()) > 0
    # key parsers should be present
    for name in ["winevtx", "winreg", "prefetch", "mft"]:
        assert name in kb.all_parser_names(), f"missing parser: {name}"


def test_parser_has_dfir_metadata():
    kb = PlasoKnowledgeBase()
    p = kb.get_parser("winevtx")
    assert p is not None
    assert len(p.dfir_use_cases) > 0
    assert "incident" in p.scenarios
    # check key use case
    assert any("4624" in uc for uc in p.dfir_use_cases)


def test_parsers_for_scenario():
    kb = PlasoKnowledgeBase()
    incident_parsers = kb.parsers_for_scenario("incident")
    assert len(incident_parsers) > 0
    names = {p.name for p in incident_parsers}
    assert "winevtx" in names
    assert "winreg" in names


def test_get_preset():
    kb = PlasoKnowledgeBase()
    preset = kb.get_preset("ransomware")
    assert "winevtx" in preset
    assert "mft" in preset
    assert "usnjrnl" in preset

    full = kb.get_preset("windows_full")
    assert "winevtx" in full
    assert "winreg" in full
    assert "prefetch" in full

    # fallback
    fallback = kb.get_preset("nonexistent")
    assert "winevtx" in fallback  # windows_triage default


def test_find_parsers_for_artifact():
    kb = PlasoKnowledgeBase()
    evtx_parsers = kb.find_parsers_for_artifact("evtx")
    assert any(p.name == "winevtx" for p in evtx_parsers)

    reg_parsers = kb.find_parsers_for_artifact("NTUSER")
    assert any(p.name == "winreg" for p in reg_parsers)


def test_format_for_llm():
    kb = PlasoKnowledgeBase()
    text = kb.format_for_llm("incident")
    assert "PLASO PARSER KNOWLEDGE BASE" in text
    assert "winevtx" in text
    assert "preset" in text.lower()

    text2 = kb.format_for_llm()
    assert "winevtx" in text2


def test_presets_have_key_parsers():
    for scenario, preset in PARSER_PRESETS.items():
        assert "winevtx" in preset or "winreg" in preset, \
            f"preset {scenario} missing core parsers"