from scheduler.resources.__resource import Resource  # noqa

# Load in all resources
import pkgutil
import importlib
import os
pkgpath = os.path.dirname(__file__)
for _, name, _ in pkgutil.iter_modules([pkgpath]):
    if not name.startswith('__'):
        importlib.import_module('.{}'.format(name), 'scheduler.resources')
