import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename
import psutil

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def check_disk_space():
    disk = psutil.disk_usage('/')
    return disk.free > 1024 * 1024 * 100

def check_system_resources():
    memory = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent()
    return memory.percent < 90 and cpu_percent < 90

@app.route('/upload/insecure', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return 'File uploaded successfully', 200

@app.route('/upload/secure', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    max_size = 10 * 1024 * 1024
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > max_size:
        return 'File too large (max 10MB)', 400

    if not check_system_resources():
        return 'Server is busy, try again later', 503

    if not check_disk_space():
        return 'Insufficient disk space', 507

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        with open(filepath, 'wb') as f:
            chunk_size = 8192
            while True:
                chunk = file.stream.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                
                if not check_system_resources():
                    os.remove(filepath)
                    return 'Server resources exceeded during upload', 503
                
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return f'Upload failed: {str(e)}', 500

    return 'File uploaded successfully', 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 