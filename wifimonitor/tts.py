import Queue
import os
import subprocess
import tempfile
import threading

import gtts
import pyttsx


speak_queue = Queue.Queue()
engine = pyttsx.init()
cachedir = tempfile.mkdtemp(prefix='wifimon')


def _speak():
    while 1:
        string, lang = speak_queue.get()
        try:
            filename = os.path.join(cachedir, hashlib.md5(string).hexdigest())
            if not os.exists(filename):
                t = gtts.gTTS(string, lang=lang)
                t.save(filename)
            subprocess.Popen(['mpg321', '-q', filename]).wait()
        except:
            engine.say(string)
            engine.runAndWait()
        finally:
            speak_queue.task_done()


def speak(string, lang='en'):
    speak_queue.put((string, lang))


thread = threading.Thread(target=_speak)
thread.setDaemon(True)
thread.start()
