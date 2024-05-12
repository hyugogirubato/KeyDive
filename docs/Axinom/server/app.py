import time
from pathlib import Path

from flask import Flask, Response, redirect

RESPONSE_PATH = Path() / 'response.json'

app = Flask(__name__)


def read_file() -> bytes:
    return RESPONSE_PATH.read_bytes() if RESPONSE_PATH.is_file() else b''


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    count = 0
    while count < 50:
        content = read_file()
        if content:
            return Response(status=200, content_type='application/json', response=content)
        time.sleep(1)
        count += 1

    return redirect('https://www.googleapis.com/certificateprovisioning/v1/devicecertificates/create', code=302)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
