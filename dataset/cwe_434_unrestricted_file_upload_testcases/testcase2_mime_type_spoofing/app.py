import os
import magic
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_MIME_TYPES = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'image/gif': ['gif']
}

def is_allowed_mime_type(file_content):
    mime = magic.from_buffer(file_content, mime=True)
    return mime in ALLOWED_MIME_TYPES

def extension_matches_mime(filename, detected_mime):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_MIME_TYPES.get(detected_mime, [])

@app.route('/upload/insecure', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    content_type = file.content_type
    if content_type in ALLOWED_MIME_TYPES:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200
    
    return 'File type not allowed', 400

@app.route('/upload/secure', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    file_content = file.read()
    file.seek(0) 

    detected_mime = magic.from_buffer(file_content, mime=True)
    
    if is_allowed_mime_type(file_content) and extension_matches_mime(file.filename, detected_mime):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return f'File uploaded successfully (Detected MIME: {detected_mime})', 200
    
    return f'Invalid file type or content (Detected MIME: {detected_mime})', 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 