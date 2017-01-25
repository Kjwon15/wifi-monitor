import hashlib
import os
import requests
import subprocess
import tempfile

import pyttsx

from multiprocessing.pool import ThreadPool


API_URL = 'https://api.voicerss.org/'
API_KEY = '80b6bc3bffb3432caf35b54b5078e2e3'


pool = ThreadPool()
engine = pyttsx.init()
cachedir = os.path.join(tempfile.gettempdir(), 'wifimon')
if not os.path.exists(cachedir):
    os.mkdir(cachedir)


def async(decorated):

    def send(*args, **kwargs):
        return pool.apply_async(decorated, args, kwargs)

    return send


@async
def speak(string, lang='en-us'):
    filename = os.path.join(cachedir, hashlib.md5(string).hexdigest())
    if os.path.exists(filename):
        subprocess.Popen(['mpg321', '-q', filename]).wait()
    else:
        try:
            resp = requests.post(API_URL, {
                'key': API_KEY,
                'src': string,
                'hl': lang,
                'f': '44khz_16bit_mono',
            })
            if resp.headers['Content-Type'].startswith('text'):
                raise Exception('API error')
            with open(filename, 'w') as fp:
                fp.write(resp.content)
        except Exception as e:
            print(repr(e))
            engine.say(string)
            engine.runAndWait()

        else:
            subprocess.Popen(['mpg321', '-q', filename]).wait()
