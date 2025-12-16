import os
from langchain_openai import ChatOpenAI
from configs.llm_config import LLMConfig

class LLMService:
    @staticmethod
    def get_llm(model_name: str = None, temperature: float = None) -> ChatOpenAI:
        """
        Get a configured ChatOpenAI instance.
        """
        api_key = LLMConfig.OPENAI_API_KEY
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
            
        base_url = LLMConfig.OPENAI_BASE_URL
        
        # Override defaults if provided
        # We can also add default model from config in the future if needed, 
        # but callers usually pass specific models (Static vs Verification)
        
        return ChatOpenAI(
            model=model_name,
            temperature=temperature if temperature is not None else 0.1,
            api_key=api_key,
            base_url=base_url if base_url else None,
            request_timeout=LLMConfig.REQUEST_TIMEOUT
        )
