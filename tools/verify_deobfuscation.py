
import os
import sys

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from llm.deobfuscator_agent import DeobfuscatorAgent

def verify():
    print("🔬 Starting Deobfuscation Verification...")
    
    agent = DeobfuscatorAgent()
    
    # Read obfuscated file
    obfuscated_path = "tmp/simple_obfuscated.js"
    if not os.path.exists(obfuscated_path):
        print(f"❌ Error: {obfuscated_path} not found.")
        return
        
    with open(obfuscated_path, 'r') as f:
        obfuscated_code = f.read()
        
    print(f"\n📄 Obfuscated Input (first 100 chars):\n{obfuscated_code[:100]}...\n")
    
    # 1. Test Deobfuscation
    print("1️⃣  Running de4js deobfuscation...")
    deobfuscated = agent._deobfuscate_code(obfuscated_code)
    used_llm_deobfuscation = False
    
    if deobfuscated == obfuscated_code:
        print("❌ Deobfuscation tool failed (no change).")
        
        if agent._is_likely_obfuscated(obfuscated_code):
            print("⚠️  Code detected as obfuscated. Attempting LLM Fallback...")
            deobfuscated = agent._llm_deobfuscate(obfuscated_code)
            used_llm_deobfuscation = True
        else:
            print("ℹ️ Code not detected as obfuscated (heuristic failed).")
    else:
        print("✅ Deobfuscation tool successful (code changed).")
        
    print(f"\n📄 Deobfuscated Output (first 100 chars):\n{deobfuscated[:100]}...\n")
        
    # 2. Test LLM Refinement (only if tool was used, LLM deobfuscation does both)
    if not used_llm_deobfuscation and deobfuscated != obfuscated_code:
        print("2️⃣  Running LLM Refinement...")
        refined = agent._refine_with_llm(deobfuscated)
    else:
        refined = deobfuscated
        print("2️⃣  Skipping separate refinement (already done by LLM or failed).")

    
    print("\n📄 Final Output:")
    print("-" * 40)
    print(refined)
    print("-" * 40)
    
    # Checks
    if "Hello World" in refined:
        print("\n✅ Found 'Hello World' in refined code.")
    else:
        print("\n❌ 'Hello World' not found in refined code.")
        
    if "function hello" in refined or "const hello" in refined or "let hello" in refined:
        print("✅ Function name seems restored (or close enough).")
        
    print("\n🏁 Verification Complete.")

if __name__ == "__main__":
    verify()
