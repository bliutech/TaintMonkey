import os
import re
from flask import Flask, request, redirect, url_for, send_from_directory

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/insecure/upload', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    filename = file.filename
    
    # basic check of end text, can be bypassed
    if filename.lower().endswith(('.txt', '.md', '.html')):
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('uploaded_file', filename=filename))
    else:
        return 'File type not allowed.', 400

@app.route('/secure/upload', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    filename = file.filename
    
    allowed_extensions = {'txt', 'md', 'html'}
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return 'Only text files are allowed', 400
    
    content = file.read().decode('utf-8', errors='ignore')
    file.seek(0)
    
    # additional level search for specfic scripts / commands
    if re.search(r'<script|<\?php|eval\(|exec\(|system\(|passthru\(|shell_exec\(', content, re.IGNORECASE):
        return 'File content contains potentially malicious code', 400
    
    if filename.lower().endswith('.html'):
        if re.search(r'<iframe|javascript:|onerror=|onload=|onclick=', content, re.IGNORECASE):
            return 'HTML file contains potentially malicious elements', 400
    
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return redirect(url_for('uploaded_file', filename))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 