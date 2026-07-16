import os
import ast

def get_functions_from_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        tree = ast.parse(code)
        funcs = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                docstring = ast.get_docstring(node) or "Tidak ada deskripsi spesifik untuk fungsi ini."
                funcs.append({'name': node.name, 'doc': docstring.split('\n')[0][:150]})
            elif isinstance(node, ast.ClassDef):
                for subnode in node.body:
                    if isinstance(subnode, ast.FunctionDef):
                        docstring = ast.get_docstring(subnode) or "Tidak ada deskripsi spesifik untuk metode ini."
                        funcs.append({'name': f"{node.name}.{subnode.name}", 'doc': docstring.split('\n')[0][:150]})
        return funcs
    except Exception as e:
        return []

files_to_parse = ['app.py', 'database.py', 'snmp_worker.py', 'unifi_client.py']

html_out = """
<section id="function-reference" class="section fade-in" style="margin-top: 60px;">
    <div class="section-header" style="display: flex; align-items: center; gap: 16px; margin-bottom: 30px;">
        <div class="section-icon" style="background: var(--accent-gradient); width: 48px; height: 48px; border-radius: var(--radius-md); display: flex; align-items: center; justify-content: center; color: white; font-size: 24px; box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);">
            <i class="bi bi-code-slash"></i>
        </div>
        <div>
            <h2 style="margin: 0; font-size: 24px; border: none; padding: 0;">Referensi Fungsi & API</h2>
            <p class="section-subtitle" style="margin: 4px 0 0 0; color: var(--text-muted); font-size: 15px;">Daftar lengkap metode dan fungsi sistem (Auto-Generated)</p>
        </div>
    </div>
"""

for pyfile in files_to_parse:
    funcs = get_functions_from_file(f'/mnt/d/PVT/PERSONAL PROJECT/netmon/{pyfile}')
    if not funcs: continue
    
    html_out += f"""
    <div class="file-reference-card" style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); margin-bottom: 30px; overflow: hidden; box-shadow: var(--shadow); transition: var(--transition);">
        <div class="file-header" style="background: var(--bg-secondary); padding: 16px 24px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 12px;">
            <i class="bi bi-filetype-py" style="color: var(--accent-color); font-size: 20px;"></i>
            <h3 style="margin: 0; font-family: var(--font-mono); font-size: 18px; color: var(--text-main); border: none; padding: 0;">{pyfile}</h3>
            <span style="margin-left: auto; font-size: 12px; color: var(--text-muted); background: var(--bg-primary); padding: 4px 10px; border-radius: 20px; border: 1px solid var(--border-color);">{len(funcs)} functions</span>
        </div>
        <div class="file-body" style="padding: 24px; display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;">
    """
    
    for f in funcs:
        html_out += f"""
            <div class="function-item" style="padding: 14px 16px; background: var(--bg-primary); border-left: 3px solid var(--accent-color); border-radius: 6px; border-top: 1px solid var(--border-color); border-right: 1px solid var(--border-color); border-bottom: 1px solid var(--border-color); transition: var(--transition);">
                <div style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-color); font-size: 13.5px; margin-bottom: 6px; word-break: break-all;">
                    <i class="bi bi-braces" style="opacity: 0.5; margin-right: 4px;"></i>{f['name']}
                </div>
                <div style="font-size: 13px; color: var(--text-muted); line-height: 1.5;">{f['doc']}</div>
            </div>
        """
        
    html_out += """
        </div>
    </div>
    """
    
html_out += "</section>\n"

readme_html_path = '/mnt/d/PVT/PERSONAL PROJECT/netmon/README.html'
try:
    with open(readme_html_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Find the start of our previous insertion
    marker = "<hr style='border:none; border-top: 1px solid var(--border-color); margin: 40px 0;'/>"
    if marker in content:
        parts = content.split(marker)
        # Rebuild with new HTML
        new_content = parts[0] + html_out + "\n</main>\n</body>\n</html>"
        with open(readme_html_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("Successfully beautified README.html")
    else:
        print("Marker not found.")
            
except Exception as e:
    print("Error updating README.html:", e)
