import glob
import imp
import os

class PluginManager(object):

    def __init__(self):
        self.on_connect_handlers = []
        self.on_disconnect_handlers = []
        self.on_update_handlers = []

    def load_plugins(self, dir):
        for filename in glob.glob(os.path.join(dir, '*.py')):
            module = imp.load_source('plugin', filename)

            on_connect = getattr(module, 'on_connect', None)
            if on_connect:
                self.on_connect_handlers.append(on_connect)

            on_disconnect = getattr(module, 'on_disconnect', None)
            if on_disconnect:
                self.on_disconnect_handlers.append(on_disconnect)

            on_update = getattr(module, 'on_update', None)
            if on_update:
                self.on_update_handlers.append(on_update)

    def process_connect(self, *args, **kwargs):
        for handler in self.on_connect_handlers:
            handler(*args, **kwargs)

    def process_disconnect(self, *args, **kwargs):
        for handler in self.on_disconnect_handlers:
            handler(*args, **kwargs)

    def process_update(self, *args, **kwargs):
        for handler in self.on_update_handlers:
            handler(*args, **kwargs)
