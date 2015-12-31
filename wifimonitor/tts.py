import Queue
import hashlib
import os
import requests
import subprocess
import tempfile
import threading

import pyttsx


API_URL = 'https://api.voicerss.org/'
API_KEY = '80b6bc3bffb3432caf35b54b5078e2e3'


speak_queue = Queue.Queue()
engine = pyttsx.init()
cachedir = os.path.join(tempfile.gettempdir(), 'wifimon')
if not os.path.exists(cachedir):
    os.mkdir(cachedir)


def _speak():
    while 1:
        string, lang = speak_queue.get()
        filename = os.path.join(cachedir, hashlib.md5(string).hexdigest())
        if os.path.exists(filename):
            subprocess.Popen(['mpg321', '-q', filename]).wait()
            speak_queue.task_done()
        else:
            try:
                resp = requests.get(API_URL, {
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
            finally:
                speak_queue.task_done()


def speak(string, lang='en-us'):
    speak_queue.put((string, lang))


thread = threading.Thread(target=_speak)
thread.setDaemon(True)
thread.start()
