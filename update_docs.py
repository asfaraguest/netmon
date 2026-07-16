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
func_list_html = "<div class='section' style='margin-top: 40px;'>\n<h2>Daftar Fungsi per File Code (Auto-Generated)</h2>\n"

for pyfile in files_to_parse:
    funcs = get_functions_from_file(f'/mnt/d/PVT/PERSONAL PROJECT/netmon/{pyfile}')
    if not funcs: continue
    func_list_html += f"<h3>{pyfile}</h3>\n<ul>\n"
    for f in funcs:
        func_list_html += f"<li><strong><code>{f['name']}</code></strong>: {f['doc']}</li>\n"
    func_list_html += "</ul>\n"
func_list_html += "</div>\n"

# Update README.md
readme_path = '/mnt/d/PVT/PERSONAL PROJECT/netmon/README.md'
try:
    with open(readme_path, 'r', encoding='utf-8') as f:
        readme_content = f.read()
        
    new_feature = "| **Real Record Bucketing** | Accurate point-to-point raw traffic sampling for Backbone and Router charts without generic averaging |\n"
    if "Real Record Bucketing" not in readme_content:
        readme_content = readme_content.replace("| **SNMP Auto-Polling** |", new_feature + "| **SNMP Auto-Polling** |")
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
except Exception as e:
    print("Error updating README.md:", e)

# Update README.html
readme_html_path = '/mnt/d/PVT/PERSONAL PROJECT/netmon/README.html'
try:
    with open(readme_html_path, 'r', encoding='utf-8') as f:
        readme_html_content = f.read()
        
    if "Daftar Fungsi per File Code" not in readme_html_content:
        parts = readme_html_content.rsplit("</body>", 1)
        if len(parts) == 2:
            new_html = parts[0] + f"<hr/>\n{func_list_html}\n" + "</body>" + parts[1]
            with open(readme_html_path, 'w', encoding='utf-8') as f:
                f.write(new_html)
except Exception as e:
    print("Error updating README.html:", e)

# Update development_documentation.html
dev_doc_path = '/mnt/d/PVT/PERSONAL PROJECT/netmon/development_documentation.html'
try:
    with open(dev_doc_path, 'r', encoding='utf-8') as f:
        dev_doc_content = f.read()
        
    new_dev_update = """
    <div style='margin-top: 30px; border-top: 2px solid #007aff; padding-top: 20px;'>
    <h3>Fase Penyempurnaan: Real Record Bucketing & Codebase Verification</h3>
    <p>
      <strong>Objektif:</strong> Meningkatkan akurasi penyajian laporan grafik Backbone dan Router individual menggunakan metode Raw Record Bucketing untuk filter rentang waktu 24 Jam, 7 Hari, dan 1 Bulan.<br>
      <strong>Implementasi & Verifikasi:</strong>
      <ul>
        <li>Membuat bucketing raw metric menggunakan <code>defaultdict</code> berdasarkan rentang waktu di dalam siklus loop router.</li>
        <li>Sinkronisasi integrasi toggle UI (<code>reports.html</code>) antara grafik Backbone dan grafik Router.</li>
        <li>Penggunaan parameter <code>fill: true</code> dan <code>pointRadius: 0</code> pada Chart.js untuk optimalisasi render <em>raw data</em> kepadatan tinggi tanpa <em>lag</em> visual.</li>
        <li>Kondisional per-router (<code>include_in_aggregate = 1</code>) diterapkan langsung pada agregasi <code>rx</code> dan <code>tx</code> di sisi backend <code>database.py</code>.</li>
        <li>Uji komprehensif dilakukan menggunakan <code>verify_backbone.py</code> via simulasi input DB, menghasilkan konfirmasi stabilitas yang lolos tanpa kesalahan (<strong>LULUS</strong>).</li>
        <li>Penyempurnaan arsitektur database (mode WAL, timeout) dan sanitasi template UI (<code>esc()</code>) meminimalisir peluang error lintas-request dan ancaman XSS.</li>
      </ul>
    </p>
    </div>
    """
    if "Fase Penyempurnaan: Real Record Bucketing" not in dev_doc_content:
        parts = dev_doc_content.rsplit("</body>", 1)
        if len(parts) == 2:
            new_dev_doc = parts[0] + f"\n{new_dev_update}\n" + "</body>" + parts[1]
            with open(dev_doc_path, 'w', encoding='utf-8') as f:
                f.write(new_dev_doc)
except Exception as e:
    print("Error updating development_documentation.html:", e)

print("Documentation successfully updated!")
