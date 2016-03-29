from django.core.management.base import BaseCommand
from django.shortcuts import get_object_or_404

from api.models import Key, App, Domain, Certificate, Config


class Command(BaseCommand):
    """Management command for publishing Deis platform state from the database
    to k8s.
    """
    def handle(self, *args, **options):
        """Publishes Deis platform state from the database to etcd."""
        print("Publishing DB state to k8s...")
        for model in (Key, App, Domain, Certificate, Config):
            for obj in model.objects.all():
                obj.save()

        # certificates have to be attached to domains to create k8s secrets
        for cert in Certificate.objects.all():
            for domain in cert.domains:
                domain = get_object_or_404(Domain, domain=domain)
                cert.attach_in_kubernetes(domain)

        print("Done Publishing DB state to k8s.")
