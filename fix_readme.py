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
                docstring = ast.get_docstring(node) or "Tidak ada deskripsi."
                funcs.append({'name': node.name, 'doc': docstring.split('\n')[0][:150]})
            elif isinstance(node, ast.ClassDef):
                for subnode in node.body:
                    if isinstance(subnode, ast.FunctionDef):
                        docstring = ast.get_docstring(subnode) or "Tidak ada deskripsi."
                        funcs.append({'name': f"{node.name}.{subnode.name}", 'doc': docstring.split('\n')[0][:150]})
        return funcs
    except Exception as e:
        return []

files_to_parse = ['app.py', 'database.py', 'snmp_worker.py', 'unifi_client.py']
func_list_html = "<div class='section' style='margin-top: 40px;' id='function-list-doc'>\n<h2>Daftar Fungsi per File Code (Auto-Generated)</h2>\n"

for pyfile in files_to_parse:
    funcs = get_functions_from_file(f'/mnt/d/PVT/PERSONAL PROJECT/netmon/{pyfile}')
    if not funcs: continue
    func_list_html += f"<h3>{pyfile}</h3>\n<ul>\n"
    for f in funcs:
        func_list_html += f"<li><strong><code>{f['name']}</code></strong>: {f['doc']}</li>\n"
    func_list_html += "</ul>\n"
func_list_html += "</div>\n"

readme_html_path = '/mnt/d/PVT/PERSONAL PROJECT/netmon/README.html'
try:
    with open(readme_html_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Remove the old incorrectly placed block if it exists (it starts with <hr/>\n<div class='section' style='margin-top: 40px;'>\n<h2>Daftar Fungsi)
    # The split might be tricky, so let's just find the first <hr/>\n<div class='section' style='margin-top: 40px;'>
    # and truncate the file there, then add back </body></html>
    
    marker = "<hr/>\n<div class='section' style='margin-top: 40px;'>\n<h2>Daftar Fungsi"
    if marker in content:
        content = content.split(marker)[0] + "\n</body>\n</html>\n"
        
    # Now insert into the right place (before </main>)
    if "Daftar Fungsi per File Code" not in content:
        parts = content.rsplit("</main>", 1)
        if len(parts) == 2:
            new_html = parts[0] + f"<hr style='border:none; border-top: 1px solid var(--border-color); margin: 40px 0;'/>\n{func_list_html}\n" + "</main>" + parts[1]
            with open(readme_html_path, 'w', encoding='utf-8') as f:
                f.write(new_html)
            print("Successfully fixed README.html placement")
        else:
            print("Could not find </main> in README.html")
            
except Exception as e:
    print("Error updating README.html:", e)
