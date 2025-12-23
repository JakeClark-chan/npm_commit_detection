
"""
Prompts for the Deobfuscation Agent.
"""

# Prompt to check if code is obfuscated (if heuristics are insufficient)
DETECTION_SYSTEM_PROMPT = """You are an expert in detecting obfuscated code.
Analyze the provided code snippet and determine if it is obfuscated.
Look for:
- Random/meaningless variable names (e.g., _0x1234, a, b)
- Hexadecimal string encoding
- Control flow flattening
- Packed code / meaningless arithmetic logic
- Anti-debugging checks

Respond with a JSON object:
{
    "is_obfuscated": boolean,
    "confidence": float (0.0 to 1.0),
    "reason": "short explanation"
}
"""

DETECTION_USER_PROMPT = """
Code to analyze:
```javascript
{code}
```
"""

# Prompt to deobfuscate manually (fallback)
DEOBFUSCATION_PROMPT = """
You are an expert Code Deobfuscator.
The following JavaScript code appears to be obfuscated and automated tools failed to decode it.
Your task is to DEOBFUSCATE it manually:
1. Decode strings/arrays if possible.
2. Rename variables to meaningful names.
3. Unpack logic.
4. Format the code.

Output ONLY the deobfuscated code.

Code:
```javascript
{code}
```
"""

# Prompt to refine code (rename variables, format)
REFINEMENT_PROMPT = """
You are a Code Deobfuscator Assistant.
The following code has been mechanically deobfuscated but still has ugly variable names (e.g. _0x1234) or structure.
Your task is to RENAME variables and functions to be meaningful based on their usage, and fix indentation.
Do NOT change the logic. ONLY rename and format.
Output ONLY the cleaned code.

Code:
```javascript
{code}
```
"""
