import Queue
import hashlib
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
        filename = os.path.join(cachedir, hashlib.md5(string).hexdigest())
        if os.path.exists(filename):
            subprocess.Popen(['mpg321', '-q', filename]).wait()
            speak_queue.task_done()
        else:
            try:
                t = gtts.gTTS(string, lang=lang)
                t.save(filename)
            except:
                engine.say(string)
                engine.runAndWait()
            else:
                subprocess.Popen(['mpg321', '-q', filename]).wait()
            finally:
                speak_queue.task_done()


def speak(string, lang='en'):
    speak_queue.put((string, lang))


thread = threading.Thread(target=_speak)
thread.setDaemon(True)
thread.start()
