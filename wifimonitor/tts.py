import gtts
import tempfile
import subprocess
import threading
import Queue
import pyttsx


speak_queue = Queue.Queue()
engine = pyttsx.init()


def _speak():
    while 1:
        string, lang = speak_queue.get()
        try:
            t = gtts.gTTS(string, lang=lang)
            f = tempfile.NamedTemporaryFile()
            t.write_to_fp(f)
            f.flush()
            subprocess.Popen(['mpg321', '-q', f.name]).wait()
            f.close()
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
