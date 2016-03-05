
class AbstractSchedulerClient(object):
    """
    A generic interface to a scheduler backend.
    """

    def __init__(self, target):
        self.target = target

    def create(self, name, **kwargs):
        """Create a new container."""
        raise NotImplementedError

    def destroy(self, name):
        """Destroy a container."""
        raise NotImplementedError

    def run(self, name, image, entrypoint, command, **kwargs):
        """Run a one-off command."""
        raise NotImplementedError

    def start(self, name):
        """Start a container."""
        raise NotImplementedError

    def state(self, name):
        """Display the given job's running state."""
        raise NotImplementedError

    def stop(self, name):
        """Stop a container."""
        raise NotImplementedError
