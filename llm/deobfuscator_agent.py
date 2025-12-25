
import os
import subprocess
import logging
import re
import json
from typing import Dict, List, Optional, Tuple
from langchain_core.messages import HumanMessage, SystemMessage
from llm.service import LLMService

from configs.deobfuscation_config import DeobfuscationConfig
import prompts.deobfuscation_prompts as prompts

logger = logging.getLogger(__name__)

class DeobfuscatorAgent:
    """
    Agent responsible for detecting obfuscated code, deobfuscating it using tools,
    and refining it using LLM to make it readable.
    """
    
    def __init__(self):
        # Configuration
        self.enabled = DeobfuscationConfig.ENABLED
        self.deobfuscator_script = DeobfuscationConfig.TOOL_PATH
        
        # Initialize LLM for detection and refinement
        self.llm = LLMService.get_llm(
            model_name=DeobfuscationConfig.MODEL,
            temperature=DeobfuscationConfig.TEMPERATURE
        ) 
    
    def process_commits(self, repository, commit_shas: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Process a list of commits, looking for obfuscated files.
        """
        if not self.enabled:
            logger.info("Deobfuscation agent is disabled.")
            return {}
            
        results = {}
        
        for sha in commit_shas:
            changes = repository.get_file_changes(sha)
            commit_results = {}
            
            for change in changes:
                filename = change.filename
                # Only check JS/TS files
                if not any(filename.endswith(ext) for ext in ['.js', '.mjs', '.cjs', '.ts']):
                    continue
                
                try:
                    content = repository._run_git("show", f"{sha}:{filename}")
                except Exception:
                    continue
                    
                if not content or len(content) < DeobfuscationConfig.MIN_FILE_LENGTH:
                    continue
                
                # 1. SCAN: Check if code needs deobfuscation
                is_obfuscated, confidence = self._scan_for_obfuscation(content)
                
                if not is_obfuscated:
                    continue
                    
                logger.info(f"Obfuscation detected in {sha[:8]}:{filename} (confidence: {confidence:.2f})")
                
                # 2. TOOL: Run deobfuscation tool
                deobfuscated_content = self._run_deobfuscation_tool(content)
                
                # 3. CHECK & REFINE
                if deobfuscated_content != content:
                    logger.info(f"   Tool successfully modified content.")
                    # Tool worked, now refine
                    refined = self._refine_with_llm(deobfuscated_content)
                    commit_results[filename] = refined
                else:
                    logger.info(f"   Tool failed to modify content. Attempting LLM fallback...")
                    # Tool failed, try LLM deobfuscation
                    deobfuscated_llm = self._llm_deobfuscate(content)
                    commit_results[filename] = deobfuscated_llm
            
            if commit_results:
                results[sha] = commit_results
                
        return results

    def _scan_for_obfuscation(self, code: str) -> Tuple[bool, float]:
        """
        Check if code is obfuscated using heuristics + partial LLM check if needed.
        """
        # 1. Fast heuristics
        heuristic_score = 0.0
        if "_0x" in code: heuristic_score += 0.4
        if "\\x" in code: heuristic_score += 0.3
        
        # Check density of lines (packed code)
        lines = code.splitlines()
        avg_line_len = len(code) / max(len(lines), 1)
        if avg_line_len > 200: heuristic_score += 0.3
        
        # Check for specific array rotation patterns common in obfuscator.io
        if "push" in code and "shift" in code and "while" in code:
            heuristic_score += 0.2
            
        if heuristic_score >= 0.5:
            return True, heuristic_score
            
        # 2. If borderline, ask LLM (optional, but requested "LLM request")
        # Optimization: Only ask if code is small enough/suspicious but not certain
        if 0.2 <= heuristic_score < 0.5 and len(code) < 5000:
             return self._llm_check_obfuscation(code)
             
        return False, heuristic_score
        
    def _llm_check_obfuscation(self, code: str) -> Tuple[bool, float]:
        """Ask LLM if code is obfuscated"""
        try:
            prompt = prompts.DETECTION_USER_PROMPT.format(code=code[:2000]) # Check first 2k chars
            messages = [
                SystemMessage(content=prompts.DETECTION_SYSTEM_PROMPT),
                HumanMessage(content=prompt)
            ]
            response = self.llm.invoke(messages)
            
            # extract json
            content = response.content.replace("```json", "").replace("```", "").strip()
            # simple json extraction
            if "{" in content:
                content = content[content.find("{"):content.rfind("}")+1]
                data = json.loads(content)
                return data.get("is_obfuscated", False), data.get("confidence", 0.0)
                
        except Exception as e:
            logger.warning(f"LLM detection failed: {e}")
            
        return False, 0.0

    def _llm_deobfuscate(self, code: str) -> str:
        """Use LLM to deobfuscate code when tool fails"""
        if len(code) > DeobfuscationConfig.MAX_FILE_LENGTH_FOR_LLM:
            code = code[:DeobfuscationConfig.MAX_FILE_LENGTH_FOR_LLM] + "\n... (truncated)"
            
        prompt = prompts.DEOBFUSCATION_PROMPT.format(code=code)
        
        try:
            messages = [HumanMessage(content=prompt)]
            response = self.llm.invoke(messages)
            
            cleaned = response.content
            if "```" in cleaned:
                cleaned = cleaned.replace("```javascript", "").replace("```", "")
            
            return cleaned.strip()
        except Exception as e:
            logger.error(f"LLM deobfuscation failed: {e}")
            return code

    def _run_deobfuscation_tool(self, code: str) -> str:
        """
        Run the configured deobfuscation tool.
        """
        try:
            # Create temporary files
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as tmp_in:
                tmp_in.write(code)
                tmp_in_path = tmp_in.name
            
            tmp_out_path = tmp_in_path + ".out.js"
            
            # Prepare command
            # DeobfuscationConfig.TOOL_USE_CMD is a list template: ["tool", "<file-input>", "-o", "<file-output>"]
            cmd_template = DeobfuscationConfig.TOOL_USE_CMD
            cmd = []
            
            # Check if we are using the internal tool path or a global command
            tool_path = self.deobfuscator_script
            
            # If tool_path is a file that exists, we treating it as a script execution
            # This preserves backward compatibility for local dev with ts-node/node
            if os.path.exists(tool_path) and os.path.isfile(tool_path):
                 if tool_path.endswith(".ts"):
                     cmd = ["npx", "ts-node", tool_path, "-i", tmp_in_path, "-o", tmp_out_path]
                 else:
                     cmd = ["node", tool_path, "-i", tmp_in_path, "-o", tmp_out_path]
                 
                 # Set CWD to tool dir for dependencies
                 if "javascript-deobfuscator" in tool_path:
                     cwd = os.path.dirname(os.path.dirname(tool_path))
                 else:
                     cwd = os.path.dirname(tool_path)
            
            else:
                # Global command mode (CI environment)
                # We use the configured command template or fall back to tool_path as the executable
                
                # If tool_path looks like a command name (no separators), treat it as the executable
                executable = tool_path
                
                # Construct command from template
                for arg in cmd_template:
                    if arg == DeobfuscationConfig.TOOL_NAME: 
                         # Replace tool name with actual executable path/name we resolved
                         cmd.append(executable)
                    elif arg == DeobfuscationConfig.FILE_INPUT:
                        cmd.append(tmp_in_path)
                    elif arg == DeobfuscationConfig.FILE_OUTPUT:
                        cmd.append(tmp_out_path)
                    else:
                        cmd.append(arg)
                
                # If template didn't use placeholders (e.g. legacy config), try to infer reasonable default
                if cmd == cmd_template:
                     # Fallback: executable input -o output
                     cmd = [executable, tmp_in_path, "-o", tmp_out_path]
                     
                cwd = os.getcwd() # Run in current dir

            logger.info(f"Running deobfuscator: {' '.join(cmd)}")

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd
            )

            if process.returncode != 0:
                logger.warning(f"Deobfuscation tool failed: {process.stderr}")
                if os.path.exists(tmp_in_path): os.unlink(tmp_in_path)
                if os.path.exists(tmp_out_path): os.unlink(tmp_out_path)
                return code
            
            if os.path.exists(tmp_out_path):
                with open(tmp_out_path, 'r') as f:
                    result = f.read()
                os.unlink(tmp_in_path)
                os.unlink(tmp_out_path)
                return result.strip() if result.strip() else code
            else:
                if os.path.exists(tmp_in_path): os.unlink(tmp_in_path)
                return code
            
        except Exception as e:
            logger.error(f"Error running deobfuscator: {e}")
            return code

    def _refine_with_llm(self, code: str) -> str:
        """
        Use LLM to rename variables and make code more readable.
        """
        # Truncate if too long
        if len(code) > DeobfuscationConfig.MAX_FILE_LENGTH_FOR_LLM:
            code = code[:DeobfuscationConfig.MAX_FILE_LENGTH_FOR_LLM] + "\n... (truncated)"

        prompt = prompts.REFINEMENT_PROMPT.format(code=code)
        try:
            messages = [HumanMessage(content=prompt)]
            response = self.llm.invoke(messages)
            
            cleaned = response.content
            # Strip markdown code blocks if present
            if "```" in cleaned:
                cleaned = cleaned.replace("```javascript", "").replace("```", "")
            
            return cleaned.strip()
        except Exception as e:
            logger.error(f"LLM refinement failed: {e}")
            return code
