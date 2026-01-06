from .base_config import BaseConfig

class StaticAnalysisConfig(BaseConfig):
    """Configuration for Static Analysis."""
    
    MODEL = BaseConfig.get_env("LLM_MODEL", "gpt-4-turbo")
    
    # Handle empty string values with fallback
    _context_window = BaseConfig.get_env("LLM_CONTEXT_WINDOW", "128000")
    CONTEXT_WINDOW = int(_context_window) if _context_window else 128000
    
    _temperature = BaseConfig.get_env("LLM_TEMPERATURE", "0")
    TEMPERATURE = float(_temperature) if _temperature else 0.0

    # Suspicious patterns to look for
    SUSPICIOUS_PATTERNS = {
        'network': [
            r'https?://[^\s\'"]+', r'fetch\s*\(', r'axios\.', r'http\.get', r'http\.post', r'XMLHttpRequest',
        ],
        'crypto': [
            r'crypto\.createHash', r'bitcoin', r'ethereum', r'wallet', r'private.*key', r'mnemonic',
        ],
        'env': [
            r'process\.env\.', r'ENV\[', r'getenv\(',
        ],
        'eval': [
            r'\beval\s*\(', r'Function\s*\(', r'vm\.runInNewContext', r'child_process', r'exec\s*\(', r'spawn\s*\(',
        ],
        'shell': [
            r'curl\s+', r'wget\s+', r'bash\s+', r'\bsh\s+', r'powershell', r'cmd\.exe', r'/bin/sh', r'/bin/bash', r'\|\s*sh', r'\|\s*bash',
        ],
        'obfuscation': [
            r'\\x[0-9a-fA-F]{2}', r'String\.fromCharCode', r'atob\s*\(', r'Buffer\.from.*base64',
        ],
    }

    # Define ignored extensions and directories - Adjusted based on user feedback to keep scripts/configs
    IGNORED_EXTENSIONS = {
            # Documentation & Text
            '.md', '.txt', '.rst', '.license', '.ipynb',
            # Data (Keep .json as it might be package.json)
            '.lock', '.csv', '.log',
            # Web Assets
            '.html', '.css', '.scss', '.less', '.map',
            # Binary & Media
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot',
            '.mp4', '.webm', '.mp3', '.wav',
            '.zip', '.tar', '.gz', '.pdf', '.jar', '.pyc',
    }

    IGNORED_DIRECTORIES = [
            # 'test/', 'tests/', 'spec/', '__tests__/',
            'docs/', 'documentation/',
            'assets/', 'public/',
            'dist/', 'build/', 'out/', 'coverage/',
            'node_modules/', 'vendor/',
            'examples/', 'samples/', '.github/'
            # Note: .github/ intentionally NOT ignored to detect CI poisoning, and delete .vscode/ as it is not needed
    ]
