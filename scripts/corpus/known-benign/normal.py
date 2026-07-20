from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({'status': 'ok', 'message': 'Hello world'})

@app.route('/api/data', methods=['GET'])
def get_data():
    query = request.args.get('q', '')
    return jsonify({'query': query, 'results': []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
