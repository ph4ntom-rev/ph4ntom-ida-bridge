"""
Antigravity IDA Bridge — Agent Backends
===========================================
Unified, fault-tolerant backend architecture for AI Agents.
Supports OpenAI, DeepSeek, Anthropic, Gemini, and Ollama.
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Type, Union

from core.client import BridgeClient
from core.schema import SchemaLoader

# Настройка логгера
logger = logging.getLogger("Antigravity.Bridge")

# ── Флаги доступности SDK ──────────────────────────────────────────────
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    OpenAI, HAS_OPENAI = None, False

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    genai, types, HAS_GENAI = None, None, False

try:
    import ollama as ollama_sdk
    HAS_OLLAMA = True
except ImportError:
    ollama_sdk, HAS_OLLAMA = None, False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    anthropic, HAS_ANTHROPIC = None, False


# ==============================================================================
# ABSTRACT BASE CLASS
# ==============================================================================

class AgentBackend(ABC):
    """Abstract base class for all AI agent backends."""

    _registry: Dict[str, Type['AgentBackend']] = {}

    def __init__(self, client: Optional[BridgeClient] = None, schema: Optional[SchemaLoader] = None, model: Optional[str] = None):
        self.client = client or BridgeClient()
        self.schema = schema or SchemaLoader()
        self.model = model or self.get_default_model()
        self.history: List[Dict[str, Any]] = []
        self.reset()

    # ── Метаданные (Class Methods, избавляют от __new__ хаков) ──

    @classmethod
    @abstractmethod
    def get_name(cls) -> str: pass

    @classmethod
    @abstractmethod
    def get_default_model(cls) -> str: pass

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool: pass

    @classmethod
    def register(cls, name: str):
        def decorator(subclass: Type['AgentBackend']):
            cls._registry[name] = subclass
            return subclass
        return decorator

    @classmethod
    def list_backends(cls) -> dict:
        """Безопасный опрос доступных бэкендов без аллокации памяти (O(1))."""
        return {
            name: {
                "name": b_cls.get_name(),
                "model": b_cls.get_default_model(),
                "available": b_cls.is_available(),
            } for name, b_cls in cls._registry.items()
        }

    @classmethod
    def auto_select(cls) -> Optional[str]:
        priority = ["ollama", "gemini", "openai", "anthropic", "deepseek"]
        for name in priority:
            if (b_cls := cls._registry.get(name)) and b_cls.is_available():
                return name
        return None

    # ── Жизненный цикл и Интерфейс ──

    def reset(self) -> None:
        """Сброс истории для освобождения контекстного окна."""
        self.history = [{"role": "system", "content": self.get_system_prompt()}]

    @abstractmethod
    def chat(self, message: str) -> str: pass

    # ── Фабрика Инструментов (Паттерн DRY) ──

    @classmethod
    def get_common_tools(cls) -> List[Dict[str, Any]]:
        """Единый источник истины. Разные SDK конвертируют это под себя."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "call_bridge_api",
                    "description": "Call any Antigravity IDA Bridge REST endpoint.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "enum": ["GET", "POST"]},
                            "path": {"type": "string", "description": "API path"},
                            "body": {"type": "string", "description": "JSON body", "default": "{}"},
                        },
                        "required": ["method", "path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "execute_idapython",
                    "description": "Execute arbitrary IDAPython script in IDA Pro.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "script_code": {"type": "string", "description": "Python script code"},
                        },
                        "required": ["script_code"],
                    },
                },
            },
        ]

    # ── Безопасный Диспетчер Инструментов (Fault-Tolerance) ──

    def _execute_tool(self, func_name: str, func_args: Union[str, Dict[str, Any]]) -> str:
        """
        Перехватывает ошибки LLM (битый JSON) и падения Python.
        Возвращает ошибки обратно нейросети для самокоррекции.
        """
        available_functions = {
            "call_bridge_api": self.call_bridge_api,
            "execute_idapython": self.execute_idapython,
        }

        func = available_functions.get(func_name)
        if not func:
            return json.dumps({"error": f"Unknown function requested: {func_name}"})

        if isinstance(func_args, str):
            try:
                func_args = json.loads(func_args) if func_args.strip() else {}
            except json.JSONDecodeError as e:
                logger.warning(f"LLM hallucinated invalid JSON args for {func_name}")
                return json.dumps({"error": f"Invalid JSON syntax: {str(e)}. Please fix."})

        if not isinstance(func_args, dict):
            func_args = {}

        try:
            result = func(**func_args)
            return result if isinstance(result, str) else json.dumps(result)
        except TypeError as e:
            return json.dumps({"error": f"Invalid arguments passed: {str(e)}"})
        except Exception as e:
            logger.exception(f"Tool runtime exception in {func_name}")
            return json.dumps({"error": f"Execution failed internally: {str(e)}"})

    # ── Реализация Инструментов ──

    def execute_idapython(self, script_code: str) -> str:
        logger.info(f"[{self.get_name()}] Executing IDAPython script...")
        try:
            response = self.client.exec_python(script_code)
            return json.dumps(response, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Execution failed: {e}", "success": False})

    def call_bridge_api(self, method: str, path: str, body: Union[str, dict] = "{}") -> str:
        logger.info(f"[{self.get_name()}] Bridge call: {method} {path}")

        if isinstance(body, str):
            try:
                data = json.loads(body) if body.strip() and body != "{}" else None
            except json.JSONDecodeError as e:
                return json.dumps({"error": f"Malformed body JSON: {str(e)}", "success": False})
        else:
            data = body

        try:
            result = self.client.call_api(method, path, data)
            result_str = json.dumps(result, indent=2)
            logger.debug(f"Response: {result_str[:500]}..." if len(result_str) > 500 else f"Response: {result_str}")
            return result_str
        except Exception as e:
            return json.dumps({"error": str(e), "success": False})

    def get_system_prompt(self) -> str:
        instructions = (
            "You have two tools:\n"
            "1. `call_bridge_api` — Use for structured REST endpoint interactions.\n"
            "2. `execute_idapython` — Use for custom IDA logic via Python API.\n"
            "Prefer `call_bridge_api` if an endpoint exists."
        )
        return self.schema.generate_system_prompt(instructions)


# ==============================================================================
# OPENAI BACKEND
# ==============================================================================

@AgentBackend.register("openai")
class OpenAIBackend(AgentBackend):

    @classmethod
    def get_name(cls) -> str: return "OpenAI"

    @classmethod
    def get_default_model(cls) -> str: return os.environ.get("OPENAI_MODEL", "gpt-4o")

    @classmethod
    def get_api_key_env(cls) -> str: return "OPENAI_API_KEY"

    @classmethod
    def is_available(cls) -> bool: return HAS_OPENAI and bool(os.environ.get(cls.get_api_key_env()))

    def get_base_url(self) -> Optional[str]: return None

    def reset(self) -> None:
        super().reset()
        self._client = OpenAI(
            api_key=os.environ.get(self.get_api_key_env(), ""),
            base_url=self.get_base_url(),
        ) if self.is_available() else None

    def chat(self, message: str) -> str:
        if not getattr(self, "_client", None):
            return "[Error: OpenAI Client not initialized]"

        self.history.append({"role": "user", "content": message})

        for _ in range(10):  # Лимит цикла от бесконечного вызова тулов
            response = self._client.chat.completions.create(
                model=self.model,
                messages=self.history,
                tools=self.get_common_tools(),
                temperature=0.2,
            )

            msg = response.choices[0].message
            if not msg.tool_calls:
                self.history.append({"role": "assistant", "content": msg.content or ""})
                return msg.content or ""

            self.history.append(msg.model_dump(exclude_none=True))

            for tool_call in msg.tool_calls:
                result = self._execute_tool(tool_call.function.name, tool_call.function.arguments)
                self.history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })

        return "[Agent reached max iterations]"


# ==============================================================================
# DEEPSEEK BACKEND (Polymorphism)
# ==============================================================================

@AgentBackend.register("deepseek")
class DeepSeekBackend(OpenAIBackend):
    """Идеальное наследование OpenAI-совместимого бэкенда (DRY)."""

    @classmethod
    def get_name(cls) -> str: return "DeepSeek"

    @classmethod
    def get_default_model(cls) -> str: return os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

    @classmethod
    def get_api_key_env(cls) -> str: return "DEEPSEEK_API_KEY"

    def get_base_url(self) -> str: return "https://api.deepseek.com"


# ==============================================================================
# GEMINI BACKEND
# ==============================================================================

@AgentBackend.register("gemini")
class GeminiBackend(AgentBackend):

    @classmethod
    def get_name(cls) -> str: return "Gemini"

    @classmethod
    def get_default_model(cls) -> str: return os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")

    @classmethod
    def is_available(cls) -> bool: return HAS_GENAI and bool(os.environ.get("GEMINI_API_KEY"))

    def reset(self) -> None:
        super().reset()
        if not self.is_available():
            self._chat_session = None
            return

        client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY", ""))
        config = types.GenerateContentConfig(
            system_instruction=self.get_system_prompt(),
            tools=[self.execute_idapython, self.call_bridge_api],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=False),
            temperature=0.2,
        )
        self._chat_session = client.chats.create(model=self.model, config=config)

    def chat(self, message: str) -> str:
        if getattr(self, "_chat_session", None) is None:
            return "[Error: Gemini Client not initialized]"

        try:
            return self._chat_session.send_message(message).text
        except Exception as e:
            logger.exception("Gemini execution failed")
            return f"[Error: {str(e)}]"


# ==============================================================================
# OLLAMA BACKEND (LOCAL LLM)
# ==============================================================================

@AgentBackend.register("ollama")
class OllamaBackend(AgentBackend):

    @classmethod
    def get_name(cls) -> str: return "Ollama (Local)"

    @classmethod
    def get_default_model(cls) -> str: return os.environ.get("OLLAMA_MODEL", "llama3.1")

    @classmethod
    def is_available(cls) -> bool:
        if not HAS_OLLAMA:
            return False
        try:
            ollama_sdk.list()
            return True
        except Exception:
            return False

    def chat(self, message: str) -> str:
        self.history.append({"role": "user", "content": message})

        for _ in range(10):
            response = ollama_sdk.chat(
                model=self.model,
                messages=self.history,
                tools=self.get_common_tools(),
            )

            msg = response.get("message") if isinstance(response, dict) else response.message
            tool_calls = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)

            if not tool_calls:
                content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", "")
                self.history.append({"role": "assistant", "content": content})
                return content

            try:
                self.history.append(msg.model_dump(exclude_none=True))
            except AttributeError:
                self.history.append(dict(msg))

            for tool_call in tool_calls:
                tc = tool_call if isinstance(tool_call, dict) else dict(tool_call)
                func = tc.get("function", {})

                func_name = func.get("name", "") if isinstance(func, dict) else getattr(func, "name", "")
                func_args = func.get("arguments", {}) if isinstance(func, dict) else getattr(func, "arguments", {})

                result = self._execute_tool(func_name, func_args)
                self.history.append({"role": "tool", "content": result})

        return "[Agent reached max iterations]"


# ==============================================================================
# ANTHROPIC BACKEND
# ==============================================================================

@AgentBackend.register("anthropic")
class AnthropicBackend(AgentBackend):

    @classmethod
    def get_name(cls) -> str: return "Anthropic Claude"

    @classmethod
    def get_default_model(cls) -> str: return os.environ.get("ANTHROPIC_MODEL", "claude-3-7-sonnet-20250219")

    @classmethod
    def is_available(cls) -> bool: return HAS_ANTHROPIC and bool(os.environ.get("ANTHROPIC_API_KEY"))

    def reset(self) -> None:
        self.history = []
        self._system_prompt = self.get_system_prompt()
        self._client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", "")) if self.is_available() else None

    @classmethod
    def get_anthropic_tools(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": t["function"]["name"],
                "description": t["function"]["description"],
                "input_schema": t["function"]["parameters"],
            } for t in cls.get_common_tools()
        ]

    def chat(self, message: str) -> str:
        if not getattr(self, "_client", None):
            return "[Error: Client is not initialized]"

        self.history.append({"role": "user", "content": message})

        for _ in range(10):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=8192,
                system=self._system_prompt,
                tools=self.get_anthropic_tools(),
                messages=self.history,
            )

            if response.stop_reason == "tool_use":
                self.history.append({"role": "assistant", "content": response.content})

                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        result = self._execute_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

                self.history.append({"role": "user", "content": tool_results})
            else:
                text = "".join(block.text for block in response.content if hasattr(block, "text"))
                self.history.append({"role": "assistant", "content": response.content})
                return text

        return "[Agent reached max iterations]"


if __name__ == "__main__":
    # Example chat loop if run directly
    backend_name = AgentBackend.auto_select()
    if not backend_name:
        print("No AI backends available. Set API keys.")
        exit(1)

    backend_cls = AgentBackend.get_backend(backend_name)
    agent = backend_cls()
    print(f"Started interactive session with {backend_cls.get_name()} ({agent.model}).")

    while True:
        try:
            user_input = input("\n[You]> ")
            if user_input.lower() in ["quit", "exit"]:
                break
            elif user_input.lower() in ["clear", "reset"]:
                agent.reset()
                print("--- Context cleared ---")
                continue

            response = agent.chat(user_input)
            print(f"\n[Agent]> {response}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
