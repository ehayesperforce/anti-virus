from flask import Flask, request, jsonify
import os
import pyclamd
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        # Initialize the ClamAV daemon
        cd = pyclamd.ClamdNetworkSocket()
        if not cd.ping():
            return jsonify({'error': 'ClamAV daemon not available'}), 500
        scan_result = cd.scan_file(filename)
        os.remove(filename)
        if scan_result:
            return jsonify({'result': 'infected', 'details': scan_result}), 200
        else:
            return jsonify({'result': 'clean'}), 200
    return jsonify({'error': 'File type not allowed'}), 400
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)