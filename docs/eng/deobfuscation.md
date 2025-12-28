# Deobfuscation Module

## 1. Overview
Attackers frequently obfuscate malicious code to evade static detection mechanisms (heuristics and signature matching). The **Deobfuscation Module** is an agentic component designed to normalize obfuscated JavaScript code into a human-readable and machine-analyzable format before it is passed to the main Static Analyzer.

## 2. Detection Strategy
The system first performs a lightweight **Entropy Scan** to decide if deobfuscation is necessary.

**Heuristics**:
*   **Structure**: High frequency of `_0x` variables, hex escapes `\xNN`.
*   **Keywords**: Presence of `atob`, `btoa`, `eval`, `Buffer.from(..., 'base64')`.
*   **Density**: Score adjustment for "packed" code (high average line length).

$$
Score_{obfuscation} = 0.4 \times I_{_0x} + 0.3 \times I_{hex} + 0.3 \times I_{packed} + 0.5 \times I_{decoder}
$$

If $Score \ge 0.5$, the file is flagged for deobfuscation.

## 3. Deobfuscation Pipeline
Once flagged, the code undergoes a 3-stage process:

### 3.1. Stage 1: Tool-Based Deobfuscation
We utilize specialized open-source tools (e.g., `javascript-deobfuscator`, `synchrony`) to handle common packing techniques.
*   **Action**: Reverses variable renaming, un-flattens control flow, and simplifies array rotations.
*   **Result**: $Code_{stage1} = Tool(Code_{original})$

### 3.2. Stage 2: Static String Decoding
Attackers often hide payloads in Base64 or Hex strings that deobfuscation tools might expose but not decode. This stage scans $Code_{stage1}$ for encoded strings.

*   **Algorithms**:
    *   **Base64**: Scans for `[A-Za-z0-9+/=]{20,}` patterns and attempts decoding.
    *   **Hex**: Detects sequences of `\xNN` escapes and converts to ASCII.
    *   **URL/HTML**: Decodes `%XX` and HTML entities.
*   **Annotation**: Decoded strings are injected as comments next to the original code to aid the LLM context.
    ```javascript
    const payload = "ZWNobyBoYWNrZWQ="; // [DECODED BASE64]: echo hacked
    ```

### 3.3. Stage 3: LLM Refinement
If the tool output is still cryptic, the LLM is invoked to perform "Semantic Refinement".
*   **Task**: Rename variables based on context (e.g., rename `_0x1a2b` to `fetchUrl`) and simplify logic.
*   **Result**: $Code_{final} = LLM_{refine}(Code_{stage2})$

## 4. Integration
The deobfuscated content temporarily replaces the original file content in the analysis pipeline. This ensures that the Static Analysis LLM evaluates the *intent* of the code rather than its obfuscated form.
