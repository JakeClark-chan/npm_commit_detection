from .base_config import BaseConfig

class LLMConfig(BaseConfig):
    """Configuration for LLM services."""

    LLM_USE_OPENROUTER = BaseConfig.get_env("LLM_USE_OPENROUTER", "true").lower() == "true"
    if not LLM_USE_OPENROUTER: # If not using OpenRouter, use OpenAI 
        # OpenAI
        OPENAI_API_KEY = BaseConfig.get_env("OPENAI_API_KEY")
        OPENAI_BASE_URL = BaseConfig.get_env("OPENAI_BASE_URL", "https://api.openai.com/v1/")
    else: # If using OpenRouter
        # OpenRouter Configuration
        OPENROUTER_API_KEY = BaseConfig.get_env("OPENROUTER_API_KEY")
        OPENROUTER_BASE_URL = BaseConfig.get_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        
        # Provider ordering (sorted by throughput: highest first)
        # These are passed as route=provider in OpenRouter requests
        OPENROUTER_PROVIDER_ORDER = [
            "groq", # For gpt-oss-120b and llama-4 model
            "baseten", # for DeepSeek v3.2 with max token rate
            "deepinfra", # For all models available with meanable token rate
            "novita", # like deepinfra but lower token rate and lower cost
            "hyperbolic", # faster but expensive
            "together", # backup if above providers failed
            "fireworks", # like together
            "openai", # for closed-source OpenAI model
            "google-ai-studio" # for closed-source Google model, specially Gemini series
        ]

        OPENROUTER_LLM_REASONING_ENABLE = True
        
        # Disable fallbacks - only use specified providers in order
        OPENROUTER_ALLOW_FALLBACKS = True

        # Sort by throughput
        OPENROUTER_SORT_BY = "throughput"
    
    # LangSmith
    LANGSMITH_API_KEY = BaseConfig.get_env("LANGSMITH_API_KEY")
    LANGSMITH_TRACING_V2 = BaseConfig.get_env("LANGSMITH_TRACING_V2", "false").lower() == "true"
    LANGSMITH_PROJECT = BaseConfig.get_env("LANGSMITH_PROJECT", "Commit Detection")
    
    # Global LLM settings
    LLM_CHAT_COMPLETION = BaseConfig.get_env("LLM_CHAT_COMPLETION", "false").lower() == "true"
    CONCURRENT_THREADS = int(BaseConfig.get_env("CONCURRENT_THREADS", "1"))
    REQUEST_TIMEOUT = int(BaseConfig.get_env("LLM_REQUEST_TIMEOUT", "120"))
