
from .base_config import BaseConfig
import os

class DeobfuscationConfig(BaseConfig):
    """Configuration for Deobfuscation Agent."""
    FILE_INPUT = "<file-input>"
    FILE_OUTPUT = "<file-output>"

    # Enable/Disable the agent
    ENABLED = False

    # Tool to use for deobfuscation (it will be installed via npm install)
    TOOL_NAME = "obfuscator-io-deobfuscator"
    TOOL_INSTALL_GLOBAL = True

    TOOL_INSTALL_CMD = ["npm", "install", "-g", TOOL_NAME]
    
    # Path to the deobfuscator CLI tool
    # Defaulting to the local tool we set up
    _default_tool_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "tools", 
        TOOL_NAME,
        "src",
        "cli.ts"
    )
    TOOL_PATH = BaseConfig.get_env("DEOBFUSCATOR_TOOL_PATH", _default_tool_path)

    TOOL_USE_CMD = [TOOL_NAME, FILE_INPUT, "-o", FILE_OUTPUT]
    
    # LLM Settings
    MODEL = BaseConfig.get_env("DEOBFUSCATION_MODEL", BaseConfig.get_env("LLM_MODEL", "gpt-4o-mini")) # Use a fast/cheap model by default
    TEMPERATURE = BaseConfig.get_env("DEOBFUSCATION_TEMPERATURE", BaseConfig.get_env("LLM_TEMPERATURE", 0.1))
    
    # Thresholds
    MIN_FILE_LENGTH = 50
    MAX_FILE_LENGTH_FOR_LLM = 15000
