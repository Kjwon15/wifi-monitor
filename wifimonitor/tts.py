import Queue
import hashlib
import os
import subprocess
import tempfile

import gtts
import pyttsx

from multiprocessing.pool import ThreadPool


pool = ThreadPool()
engine = pyttsx.init()
cachedir = tempfile.mkdtemp(prefix='wifimon')


def async(decorated):

    def send(*args, **kwargs):
        return pool.apply_async(decorated, args, kwargs)

    return send


@async
def speak(string, lang):
    filename = os.path.join(cachedir, hashlib.md5(string).hexdigest())
    if os.path.exists(filename):
        subprocess.Popen(['mpg321', '-q', filename]).wait()
    else:
        try:
            t = gtts.gTTS(string, lang=lang)
            t.save(filename)
        except:
            engine.say(string)
            engine.runAndWait()
        else:
            subprocess.Popen(['mpg321', '-q', filename]).wait()

