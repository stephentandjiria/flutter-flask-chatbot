from flask import Flask, jsonify, request
import time
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)

@app.route('/bot', methods=['POST'])
def response():
    query = dict(request.form)['query']
    result = query + ' ' + time.ctime()
    return jsonify({'response' : result})

if __name__ == '__main__':
    app.run(host='0.0.0.0',)