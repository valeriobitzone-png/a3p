"""Agent adapters. Each one runs a task against tools the probe controls."""

from a3p.adapters.callable_agent import CallableAdapter
from a3p.adapters.langgraph_agent import LangGraphAdapter
from a3p.adapters.n8n_webhook import N8nAdapter
from a3p.adapters.openai_chat import OpenAIChatAdapter

__all__ = [
    "CallableAdapter",
    "LangGraphAdapter",
    "N8nAdapter",
    "OpenAIChatAdapter",
]
