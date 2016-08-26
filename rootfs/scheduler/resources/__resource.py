from urllib.parse import urljoin
from django.conf import settings
from .. import KubeHTTPClient


class ResourceRegistry(type):
    """
    A registry of all Resources subclassed
    """
    def __init__(cls, name, bases, nmspc):
        super().__init__(name, bases, nmspc)
        if not hasattr(cls, 'registry'):
            cls.registry = set()

        cls.registry.add(cls)
        cls.registry -= set(bases)  # Remove base classes

    # Meta methods, called on class objects:
    def __iter__(cls):
        return iter(cls.registry)


class Resource(KubeHTTPClient, metaclass=ResourceRegistry):
    api_version = 'v1'
    api_prefix = 'api'
    short_name = None

    def __init__(self):
        super().__init__(settings.SCHEDULER_URL)

    def api(self, tmpl, *args):
        """Return a fully-qualified Kubernetes API URL from a string template with args."""
        url = "/{}/{}".format(self.api_prefix, self.api_version) + tmpl.format(*args)
        return urljoin(self.url, url)
