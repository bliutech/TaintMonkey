import os
import zipfile
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_EXTRACTION_SIZE = 50 * 1024 * 1024  # 50MB
MAX_COMPRESSION_RATIO = 1000  # Max 1000:1 compression ratio

def check_zip_safety(zip_path):
    total_size = 0
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            total_size += info.file_size
            if total_size > MAX_EXTRACTION_SIZE:
                return False
            if info.file_size > 0:
                compression_ratio = info.file_size / info.compress_size
                if compression_ratio > MAX_COMPRESSION_RATIO:
                    return False
    return True

@app.route('/upload/insecure', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if not file.filename.endswith('.zip'):
        return 'Only ZIP files allowed', 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            extract_path = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted')
            zip_ref.extractall(extract_path)
        return 'File uploaded and extracted successfully', 200
    except Exception as e:
        return f'Extraction failed: {str(e)}', 500

@app.route('/upload/secure', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if not file.filename.endswith('.zip'):
        return 'Only ZIP files allowed', 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        if not check_zip_safety(filepath):
            os.remove(filepath)
            return 'Suspicious ZIP file detected (too large when extracted or abnormal compression ratio)', 400
            
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            for info in zip_ref.infolist():
                if '..' in info.filename or info.filename.startswith('/'):
                    os.remove(filepath)
                    return 'Invalid file path in ZIP', 400
                    
            extract_path = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted')
            zip_ref.extractall(extract_path)
            
        return 'File uploaded and extracted successfully', 200
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return f'Extraction failed: {str(e)}', 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 