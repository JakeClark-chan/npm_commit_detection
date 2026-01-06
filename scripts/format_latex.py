#!/usr/bin/env python3
"""
Script to add \bigbreak\noindent after regular paragraphs in LaTeX files.
"""
import re
import sys
from pathlib import Path

def should_skip_line(line: str) -> bool:
    """Check if this line should not be followed by bigbreak."""
    stripped = line.strip()
    
    # Skip empty lines
    if not stripped:
        return True
    
    # Skip comments
    if stripped.startswith('%'):
        return True
    
    # Skip LaTeX commands that shouldn't be followed by bigbreak
    skip_patterns = [
        r'^\\(section|subsection|subsubsection|paragraph|chapter)\*?\{',
        r'^\\(begin|end)\{',
        r'^\\(item|label|caption|centering|includegraphics)',
        r'^\\(toprule|midrule|bottomrule|hline)',
        r'^\\(bigbreak|noindent|newline|newpage)',
        r'^\\(KwInput|KwOutput|SetKw|Fn|ForEach|Return|If|Else)',
        r'^\\\[',  # Display math
        r'^\\\]',  # End display math
        r'^\\textbf\{.*\}$',  # Standalone textbf (like table headers)
        r'&',  # Table rows
    ]
    
    for pattern in skip_patterns:
        if re.search(pattern, stripped):
            return True
    
    # Skip lines ending with certain patterns (incomplete sentences in lists)
    if stripped.endswith('\\\\'):
        return True
    
    return False

def is_regular_paragraph(line: str) -> bool:
    """Check if this line looks like a regular text paragraph."""
    stripped = line.strip()
    
    if not stripped:
        return False
    
    # Must not start with LaTeX command (except \textbf, \textit, etc. for emphasis)
    if stripped.startswith('\\') and not stripped.startswith(('\\textbf', '\\textit', '\\texttt', '\\emph')):
        # Allow sentences that start with inline formatting
        if not re.match(r'^\\(textbf|textit|texttt|emph)\{[^}]+\}[^\\]', stripped):
            return False
    
    # Check if it's actual text content (contains Vietnamese or regular words)
    has_text = bool(re.search(r'[a-zA-ZÀ-ỹ]{3,}', stripped))
    
    return has_text

def process_file(filepath: Path) -> tuple[int, str]:
    """Process a single LaTeX file and add bigbreak/noindent after paragraphs."""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    result = []
    changes = 0
    i = 0
    
    # Track context
    in_environment = 0  # Track nested environments
    
    while i < len(lines):
        line = lines[i]
        result.append(line)
        
        # Track environments
        if '\\begin{' in line:
            in_environment += 1
        if '\\end{' in line:
            in_environment -= 1
        
        # Check if we should add bigbreak after this line
        stripped = line.strip()
        
        # Only add after regular paragraphs that are followed by blank line then more text
        if i + 2 < len(lines) and in_environment == 0:
            next_line = lines[i + 1]
            after_blank = lines[i + 2] if i + 2 < len(lines) else ""
            
            # Check pattern: paragraph -> blank line -> next paragraph
            if (is_regular_paragraph(stripped) and 
                not next_line.strip() and  # Next line is blank
                is_regular_paragraph(after_blank.strip()) and
                '\\bigbreak' not in next_line and
                '\\noindent' not in after_blank):
                
                # Skip the blank line and add bigbreak\noindent
                result.append('\n\\bigbreak\\noindent\n')
                i += 1  # Skip the original blank line
                changes += 1
        
        i += 1
    
    return changes, ''.join(result)

def main():
    chapters_dir = Path('/home/jc/scripts/npm_commit_detection/commit_detection/thesis-report-new/src/chapters')
    
    tex_files = sorted(chapters_dir.glob('*.tex'))
    
    total_changes = 0
    for filepath in tex_files:
        print(f"Processing: {filepath.name}")
        changes, new_content = process_file(filepath)
        
        if changes > 0:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"  -> Added {changes} \\bigbreak\\noindent")
            total_changes += changes
        else:
            print(f"  -> No changes needed")
    
    print(f"\nTotal changes: {total_changes}")

if __name__ == '__main__':
    main()
