from .base_config import BaseConfig

class LLMConfig(BaseConfig):
    """Configuration for LLM services."""
    
    # OpenAI
    OPENAI_API_KEY = BaseConfig.get_env("OPENAI_API_KEY")
    OPENAI_BASE_URL = BaseConfig.get_env("OPENAI_BASE_URL", "https://api.openai.com/v1/")
    
    # LangSmith
    LANGSMITH_API_KEY = BaseConfig.get_env("LANGSMITH_API_KEY")
    LANGSMITH_TRACING_V2 = BaseConfig.get_env("LANGSMITH_TRACING_V2", "false").lower() == "true"
    LANGSMITH_PROJECT = BaseConfig.get_env("LANGSMITH_PROJECT", "Commit Detection")
    
    # Global LLM settings
    LLM_CHAT_COMPLETION = BaseConfig.get_env("LLM_CHAT_COMPLETION", "false").lower() == "true"
    CONCURRENT_THREADS = int(BaseConfig.get_env("CONCURRENT_THREADS", "1"))
    REQUEST_TIMEOUT = int(BaseConfig.get_env("LLM_REQUEST_TIMEOUT", "60"))
