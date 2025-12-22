import os
from langchain_openai import ChatOpenAI
from configs.llm_config import LLMConfig

class LLMService:
    @staticmethod
    def get_llm(model_name: str = None, temperature: float = None) -> ChatOpenAI:
        """
        Get a configured ChatOpenAI instance.
        Supports both OpenAI and OpenRouter based on LLM_USE_OPENROUTER config.
        """
        
        # Check if using OpenRouter
        if LLMConfig.LLM_USE_OPENROUTER:
            api_key = LLMConfig.OPENROUTER_API_KEY
            if not api_key:
                raise ValueError("OPENROUTER_API_KEY environment variable not set")
            
            base_url = LLMConfig.OPENROUTER_BASE_URL
            
            # Build provider preferences for OpenRouter
            # https://openrouter.ai/docs#provider-routing
            extra_headers = {
                "HTTP-Referer": "https://github.com/JakeClark-chan/npm_commit_detection",
                "X-Title": "NPM Commit Detection"
            }
            
            # Add provider ordering if specified
            if LLMConfig.OPENROUTER_PROVIDER_ORDER:
                provider_order = ",".join(LLMConfig.OPENROUTER_PROVIDER_ORDER)
                extra_headers["X-Provider-Order"] = provider_order
            
            # Build extra body for provider preferences
            # OpenRouter expects 'provider' in extra_body, not model_kwargs
            extra_body = {
                "provider": {
                    "order": LLMConfig.OPENROUTER_PROVIDER_ORDER,
                    "allow_fallbacks": LLMConfig.OPENROUTER_ALLOW_FALLBACKS,
                    "sort": LLMConfig.OPENROUTER_SORT_BY
                }
            }

            if LLMConfig.OPENROUTER_LLM_REASONING_ENABLE:
                extra_body["reasoning"] = {
                    "enabled": True
                }
            
            return ChatOpenAI(
                model=model_name,
                temperature=temperature if temperature is not None else 1,
                api_key=api_key,
                base_url=base_url,
                request_timeout=LLMConfig.REQUEST_TIMEOUT,
                default_headers=extra_headers,
                extra_body=extra_body  # Use extra_body instead of model_kwargs
            )
        else:
            # Use standard OpenAI
            api_key = LLMConfig.OPENAI_API_KEY
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable not set")
                
            base_url = LLMConfig.OPENAI_BASE_URL
            
            return ChatOpenAI(
                model=model_name,
                temperature=temperature if temperature is not None else 0.1,
                api_key=api_key,
                base_url=base_url if base_url else None,
                request_timeout=LLMConfig.REQUEST_TIMEOUT
            )
