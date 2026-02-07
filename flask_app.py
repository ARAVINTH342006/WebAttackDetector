from flask import Flask, jsonify


app = Flask(__name__)


@app.route('/')
def home():
    return "Hello from Python server!"


@app.route('/api/tasks')
def tasks():
    return jsonify({"tasks": ["Task1", "Task2", "Task3"]})


if __name__ == '__main__':
    
    app.run(host='127.0.0.1', port=5000, debug=True)
