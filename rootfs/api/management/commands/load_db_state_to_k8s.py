from django.core.management.base import BaseCommand
from django.shortcuts import get_object_or_404

from api.models import Key, App, Domain, Certificate, Config
from api.exceptions import DeisException


class Command(BaseCommand):
    """Management command for publishing Deis platform state from the database
    to k8s.
    """
    def handle(self, *args, **options):
        """Publishes Deis platform state from the database to kubernetes."""
        print("Publishing DB state to kubernetes...")
        for model in (Key, App, Domain, Certificate, Config):
            for obj in model.objects.all():
                try:
                    obj.save()
                except DeisException as error:
                    print('ERROR: Problem saving to model {} for {}'
                          'due to {}'.format(str(model.__name__), str(obj), str(error)))

        # certificates have to be attached to domains to create k8s secrets
        for cert in Certificate.objects.all():
            for domain in cert.domains:
                domain = get_object_or_404(Domain, domain=domain)
                cert.attach_in_kubernetes(domain)

        # deploy applications
        print("Deploying available applications")
        for application in App.objects.all():
            rel = application.release_set.latest()
            if rel.build is None:
                print('WARNING: {} has no build associated with '
                      'its latest release. Skipping deployment...'.format(application))
                continue

            try:
                application.deploy(rel)
            except DeisException as error:
                print('ERROR: There was a problem deploying {} '
                      'due to {}'.format(application, str(error)))

        print("Done Publishing DB state to kubernetes.")
