from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sqlite3
import re
import logging
import zipfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TRASH_FOLDER'] = 'trash'
app.config['ALLOWED_EXTENSIONS'] = {"docx", "xls", "pdf", "ppt", "odt", "txt", "py", "js", "c", "java", "zip", "r", "bsv", "yaml", "xml", "word", "xl", "xss", "sql", "php"}
app.secret_key = "supersecretkey"

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TRASH_FOLDER'], exist_ok=True)

# Setup logging
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, status TEXT);")
conn.commit()
conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def scan_file(filepath):
    patterns = [
        r"SELECT\s+.*\s+FROM",  
        r"UNION\s+SELECT",       
        r"OR\s+1=1",            
        r"password_list",         
        r"requests\.post\(",  
        r"exec\(",              
        r"base64_decode\(",      
        r"<script>.*?</script>",  
        r"eval\(",              
        r"document\.cookie",     
        r"DROP\s+TABLE",        
        r"system\(",            
        r"shell_exec\(",        
    ]
    
    try:
        if filepath.endswith(('.xml', '.yaml', '.yml')):
            if scan_xml_yaml(filepath):
                logging.warning(f"Suspicious script detected in {filepath}")
                return True

        if filepath.endswith(('.docx', '.pptx', '.xls')):
            metadata_info = extract_metadata(filepath)
            for value in metadata_info.values():
                if any(re.search(p, str(value), re.IGNORECASE) for p in patterns):
                    logging.warning(f"Suspicious metadata found in {filepath}")
                    return True

        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                if re.search(pattern, content):
                    logging.warning(f"Malicious pattern detected in {filepath}")
                    return True  

    except Exception as e:
        logging.error(f"Error scanning {filepath}: {e}")

    return False

def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if allowed_file(file) and scan_file(filepath):
                os.rename(filepath, os.path.join(app.config['TRASH_FOLDER'], file))
                logging.warning(f"Moved {file} to trash due to suspicious content.")
                flash(f"Malicious file detected and moved to trash: {file}")

@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files")
    files = cursor.fetchall()
    conn.close()
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    files = request.files.getlist('file')  

    for file in files:
        if file.filename == '':
            continue

        if allowed_file(file.filename):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            if file.filename.endswith('.zip'):
                extract_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename[:-4])
                os.makedirs(extract_path, exist_ok=True)

                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)

                os.remove(filepath)  
                scan_directory(extract_path)  

            elif scan_file(filepath):  
                os.remove(filepath)
                flash(f"Warning: {file.filename} contains suspicious content and was rejected!")
                return redirect(url_for('index'))
            else:
                flash(f'{file.filename} uploaded successfully!')

            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (filename, status) VALUES (?, ?)", (file.filename, "Safe"))
            conn.commit()
            conn.close()
        else:
            flash(f'File type not allowed: {file.filename}')
    
    return redirect(url_for('index'))


@app.route('/upload-folder', methods=['POST'])
def upload_folder():
    if 'folder' not in request.files:
        flash('No folder selected')
        return redirect(request.url)

    folder_files = request.files.getlist('folder')
    if not folder_files:
        flash("No folder uploaded")
        return redirect(url_for('index'))

    folder_name = folder_files[0].filename.split('/')[0]  
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)
    os.makedirs(folder_path, exist_ok=True)

    for file in folder_files:
        if file.filename == '':
            continue

        filepath = os.path.join(folder_path, file.filename)
        file.save(filepath)

        if allowed_file(file.filename) and scan_file(filepath):
            os.remove(filepath)
            flash(f"Warning: {file.filename} contains malicious content and was rejected!")
        else:
            flash(f'{file.filename} uploaded successfully!')

    scan_directory(folder_path)  
    return redirect(url_for('index'))


@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM files WHERE id = ?", (file_id,))
    file = cursor.fetchone()

    if file:
        filename = file[0]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        trash_path = os.path.join(app.config['TRASH_FOLDER'], filename)

        if os.path.exists(file_path):
            os.rename(file_path, trash_path)

        cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        flash('File moved to trash!')

    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.environ["FLASK_RUN_FROM_CLI"] = "false"  
    scan_directory(app.config['UPLOAD_FOLDER'])
    app.run(debug=False)
