
from .base_config import BaseConfig
import os

class DeobfuscationConfig(BaseConfig):
    """Configuration for Deobfuscation Agent."""
    
    # Enable/Disable the agent
    ENABLED = BaseConfig.get_env("DEOBFUSCATION_ENABLED", "true").lower() == "true"
    
    # Path to the deobfuscator CLI tool
    # Defaulting to the local tool we set up
    _default_tool_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "tools", 
        "javascript-deobfuscator",
        "src",
        "cli.ts"
    )
    TOOL_PATH = BaseConfig.get_env("DEOBFUSCATOR_TOOL_PATH", _default_tool_path)
    
    # LLM Settings
    MODEL = BaseConfig.get_env("DEOBFUSCATION_MODEL", "gpt-4o-mini") # Use a fast/cheap model by default
    TEMPERATURE = 0.1
    
    # Thresholds
    MIN_FILE_LENGTH = 50
    MAX_FILE_LENGTH_FOR_LLM = 15000
