import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png', 'gif'}

def secure_file_validation(filename, file_content):
    if not allowed_file(filename):
        return False
    
    magic_numbers = {
        b'\xFF\xD8\xFF': 'jpg',
        b'\x89\x50\x4E\x47': 'png',
        b'\x47\x49\x46\x38': 'gif'
    }

    for magic, ext in magic_numbers.items():
        if file_content.startswith(magic):
            return filename.rsplit('.', 1)[1].lower() == ext
    return False
        
@app.route('/upload/insecure', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200
    
    return 'File type is not allowed', 400

@app.route('/upload/secure', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    content = file.read()
    file.seek(0)

    if secure_file_validation(file.filename, content):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200
    
    return 'Invalid file type or content', 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)