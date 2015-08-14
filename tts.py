import gtts
import tempfile
import subprocess


def speak(string):
    t = gtts.gTTS(string)
    f = tempfile.NamedTemporaryFile()
    t.write_to_fp(f)
    f.flush()
    subprocess.Popen(['mpg321', '-q', f.name]).wait()
    f.close()

