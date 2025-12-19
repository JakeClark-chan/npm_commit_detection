from .base_config import BaseConfig

class LLMConfig(BaseConfig):
    """Configuration for LLM services."""
    
    # OpenAI
    OPENAI_API_KEY = BaseConfig.get_env("OPENAI_API_KEY")
    OPENAI_BASE_URL = BaseConfig.get_env("OPENAI_BASE_URL", "https://api.openai.com/v1/")
    
    # OpenRouter Configuration
    OPENROUTER_API_KEY = BaseConfig.get_env("OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL = BaseConfig.get_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    
    # Provider ordering (sorted by throughput: highest first)
    # These are passed as route=provider in OpenRouter requests
    OPENROUTER_PROVIDER_ORDER = [
        "groq",
        "deepinfra", 
        "novita",
        "hyperbolic",
        "together",
    ]
    
    # Disable fallbacks - only use specified providers in order
    OPENROUTER_ALLOW_FALLBACKS = False

    # Sort by throughput
    OPENROUTER_SORT_BY = "throughput"

    LLM_USE_OPENROUTER = BaseConfig.get_env("LLM_USE_OPENROUTER", "true").lower() == "true"
    
    # LangSmith
    LANGSMITH_API_KEY = BaseConfig.get_env("LANGSMITH_API_KEY")
    LANGSMITH_TRACING_V2 = BaseConfig.get_env("LANGSMITH_TRACING_V2", "false").lower() == "true"
    LANGSMITH_PROJECT = BaseConfig.get_env("LANGSMITH_PROJECT", "Commit Detection")
    
    # Global LLM settings
    LLM_CHAT_COMPLETION = BaseConfig.get_env("LLM_CHAT_COMPLETION", "false").lower() == "true"
    CONCURRENT_THREADS = int(BaseConfig.get_env("CONCURRENT_THREADS", "1"))
    REQUEST_TIMEOUT = int(BaseConfig.get_env("LLM_REQUEST_TIMEOUT", "60"))
