import pytest

from agent import AgentBackend, build_parser


def test_backend_registry_and_lookup():
    assert {"openai", "deepseek", "gemini", "ollama", "anthropic"}.issubset(
        AgentBackend.list_backends()
    )
    assert AgentBackend.get_backend("openai").get_name() == "OpenAI"
    with pytest.raises(ValueError, match="Unknown backend"):
        AgentBackend.get_backend("missing")


def test_agent_parser_accepts_backend_and_model():
    args = build_parser().parse_args(["--backend", "openai", "--model", "example-model"])
    assert args.backend == "openai"
    assert args.model == "example-model"

