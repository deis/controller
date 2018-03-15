"""
Classes to serialize the RESTful representation of Deis API models.
"""

import json
import jmespath
import re
import jsonschema
import idna
import ipaddress
from urllib.parse import urlparse

from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework import serializers

from api import models

# proc type name is lowercase alphanumeric
# https://docs-v2.readthedocs.io/en/latest/using-workflow/process-types-and-the-procfile/#declaring-process-types
PROCTYPE_MATCH = re.compile(r'^(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)$')
PROCTYPE_MISMATCH_MSG = "Process types can only contain lowercase alphanumeric characters"
MEMLIMIT_MATCH = re.compile(
    r'^(?P<mem>(([0-9]+(MB|KB|GB|[BKMG])|0)(/([0-9]+(MB|KB|GB|[BKMG])))?))$', re.IGNORECASE)
CPUSHARE_MATCH = re.compile(
    r'^(?P<cpu>(([-+]?[0-9]*\.?[0-9]+[m]?)(/([-+]?[0-9]*\.?[0-9]+[m]?))?))$')
TAGVAL_MATCH = re.compile(r'^(?:[a-zA-Z\d][-\.\w]{0,61})?[a-zA-Z\d]$')
CONFIGKEY_MATCH = re.compile(r'^[a-z_]+[a-z0-9_]*$', re.IGNORECASE)
PROBE_SCHEMA = {
    "$schema": "http://json-schema.org/schema#",

    "type": "object",
    "properties": {
        # Exec specifies the action to take.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_execaction
        "exec": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"}
                }
            },
            "required": ["command"]
        },
        # HTTPGet specifies the http request to perform.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_httpgetaction
        "httpGet": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "port": {"type": "integer"},
                "host": {"type": "string"},
                "scheme": {"type": "string"},
                "httpHeaders": {
                    "type": "array",
                    "minItems": 0,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "value": {"type": "string"},
                        }
                    }
                }
            },
            "required": ["port"]
        },
        # TCPSocket specifies an action involving a TCP port.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_tcpsocketaction
        "tcpSocket": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
            },
            "required": ["port"]
        },
        # Number of seconds after the container has started before liveness probes are initiated.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "initialDelaySeconds": {"type": "integer"},
        # Number of seconds after which the probe times out.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "timeoutSeconds": {"type": "integer"},
        # How often (in seconds) to perform the probe.
        "periodSeconds": {"type": "integer"},
        # Minimum consecutive successes for the probe to be considered successful
        # after having failed.
        "successThreshold": {"type": "integer"},
        # Minimum consecutive failures for the probe to be considered
        # failed after having succeeded.
        "failureThreshold": {"type": "integer"},
    }
}


class JSONFieldSerializer(serializers.JSONField):
    def __init__(self, *args, **kwargs):
        self.convert_to_str = kwargs.pop('convert_to_str', True)
        super(JSONFieldSerializer, self).__init__(*args, **kwargs)

    def to_internal_value(self, data):
        """Deserialize the field's JSON data, for write operations."""
        try:
            val = json.loads(data)
        except TypeError:
            val = data
        return val

    def to_representation(self, obj):
        """Serialize the field's JSON data, for read operations."""
        for k, v in obj.items():
            if v is None:  # NoneType is used to unset a value
                continue

            try:
                if self.convert_to_str:
                    obj[k] = str(v)
            except ValueError:
                obj[k] = v
                # Do nothing, the validator will catch this later

        return obj


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'first_name', 'last_name', 'is_superuser',
                  'is_staff', 'groups', 'user_permissions', 'last_login', 'date_joined',
                  'is_active']
        read_only_fields = ['is_superuser', 'is_staff', 'groups',
                            'user_permissions', 'last_login', 'date_joined', 'is_active']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        now = timezone.now()
        user = User(
            email=validated_data.get('email'),
            username=validated_data.get('username'),
            last_login=now,
            date_joined=now,
            is_active=True
        )

        if validated_data.get('first_name'):
            user.first_name = validated_data['first_name']

        if validated_data.get('last_name'):
            user.last_name = validated_data['last_name']

        user.set_password(validated_data['password'])
        # Make the first signup an admin / superuser
        if not User.objects.filter(is_superuser=True).exists():
            user.is_superuser = user.is_staff = True

        user.save()
        return user


class AdminUserSerializer(serializers.ModelSerializer):
    """Serialize admin status for a User model."""

    class Meta:
        model = User
        fields = ['username', 'is_superuser']
        read_only_fields = ['username']


class AppSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.App` model."""

    owner = serializers.ReadOnlyField(source='owner.username')
    structure = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`AppSerializer`."""
        model = models.App
        fields = ['uuid', 'id', 'owner', 'structure', 'created', 'updated']


class BuildSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Build` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    procfile = serializers.JSONField(required=False)
    sidecarfile = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`BuildSerializer`."""
        model = models.Build
        fields = ['owner', 'app', 'image', 'sha', 'procfile', 'dockerfile', 'sidecarfile',
                  'created', 'updated', 'uuid']

    def validate_procfile(self, data):
        for key, value in data.items():
            if value is None or value == "":
                raise serializers.ValidationError("Command can't be empty for process type")

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return data

    def validate_sidecarfile(self, data):
        for key, value in data.items():
            if value is None or value == "":
                raise serializers.ValidationError("Sidecar config can't be empty for process type")

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return data


class ConfigSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Config` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    values = JSONFieldSerializer(required=False, binary=True)
    memory = JSONFieldSerializer(required=False, binary=True)
    cpu = JSONFieldSerializer(required=False, binary=True)
    tags = JSONFieldSerializer(required=False, binary=True)
    registry = JSONFieldSerializer(required=False, binary=True)
    healthcheck = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)
    routable = serializers.BooleanField(required=False)

    class Meta:
        """Metadata options for a :class:`ConfigSerializer`."""
        model = models.Config
        fields = '__all__'

    def validate_values(self, data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(CONFIGKEY_MATCH, key):
                raise serializers.ValidationError(
                    "Config keys must start with a letter or underscore and "
                    "only contain [A-z0-9_]")

            # Validate PORT
            if key == 'PORT':
                if not str(value).isnumeric():
                    raise serializers.ValidationError('PORT can only be a numeric value')
                elif int(value) not in range(1, 65536):
                    # check if hte port is between 1 and 65535. One extra added for range()
                    # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_serviceport
                    raise serializers.ValidationError('PORT needs to be between 1 and 65535')

            # Validate HEALTHCHECK_*
            if key == 'HEALTHCHECK_URL':
                # Only Path information is supported, not query / anchor or anything else
                # Path is the only thing Kubernetes supports right now
                # See https://github.com/deis/controller/issues/774
                uri = urlparse(value)

                if not uri.path:
                    raise serializers.ValidationError(
                        '{} is missing a URI path (such as /healthz). '
                        'Without it no health check can be done'.format(key)
                    )

                # Disallow everything but path
                # https://docs.python.org/3/library/urllib.parse.html
                if uri.query or uri.fragment or uri.netloc:
                    raise serializers.ValidationError(
                        '{} can only be a URI path (such as /healthz) that does not contain '
                        'other things such as query params'.format(key)
                    )
            elif key.startswith('HEALTHCHECK_') and not str(value).isnumeric():
                # all other healthchecks are integers
                raise serializers.ValidationError('{} can only be a numeric value'.format(key))

        return data

    def validate_memory(self, data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

            if not re.match(MEMLIMIT_MATCH, str(value)):
                raise serializers.ValidationError(
                    "Memory limit format: <number><unit> or <number><unit>/<number><unit>, "
                    "where unit = B, K, M or G")

        return data

    def validate_cpu(self, data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

            shares = re.match(CPUSHARE_MATCH, str(value))
            if not shares:
                raise serializers.ValidationError(
                    "CPU limit format: <value> or <value>/<value>, where value must be a numeric")

        return data

    def validate_tags(self, data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            # split key into a prefix and name
            if '/' in key:
                prefix, name = key.split('/')
            else:
                prefix, name = None, key

            # validate optional prefix
            if prefix:
                if len(prefix) > 253:
                    raise serializers.ValidationError(
                        "Tag key prefixes must 253 characters or less.")

                for part in prefix.split('/'):
                    if not re.match(TAGVAL_MATCH, part):
                        raise serializers.ValidationError(
                            "Tag key prefixes must be DNS subdomains.")

            # validate required name
            if not re.match(TAGVAL_MATCH, name):
                raise serializers.ValidationError(
                    "Tag keys must be alphanumeric or \"-_.\", and 1-63 characters.")

            # validate value if it isn't empty
            if value and not re.match(TAGVAL_MATCH, str(value)):
                raise serializers.ValidationError(
                    "Tag values must be alphanumeric or \"-_.\", and 1-63 characters.")

        return data

    def validate_registry(self, data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(CONFIGKEY_MATCH, key):
                raise serializers.ValidationError(
                    "Config keys must start with a letter or underscore and "
                    "only contain [A-z0-9_]")

        return data

    def validate_healthcheck(self, data):
        for procType, healthcheck in data.items():
            if healthcheck is None:
                continue
            for key, value in healthcheck.items():
                if value is None:
                    continue
                if key not in ['livenessProbe', 'readinessProbe']:
                    raise serializers.ValidationError(
                        "Healthcheck keys must be either livenessProbe or readinessProbe")
                try:
                    jsonschema.validate(value, PROBE_SCHEMA)
                except jsonschema.ValidationError as e:
                    raise serializers.ValidationError(
                        "could not validate {}: {}".format(value, e.message))

            # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_probe
            # liveness only supports successThreshold=1, no other value
            # This is not in the schema since readiness supports other values
            threshold = jmespath.search('livenessProbe.successThreshold', healthcheck)
            if threshold is not None and threshold != 1:
                raise serializers.ValidationError(
                    'livenessProbe successThreshold can only be 1'
                )

        return data


class ReleaseSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Release` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`ReleaseSerializer`."""
        model = models.Release
        fields = '__all__'


class KeySerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Key` model."""

    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a KeySerializer."""
        model = models.Key
        fields = '__all__'


class DomainSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Domain` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`DomainSerializer`."""
        model = models.Domain
        fields = ['owner', 'created', 'updated', 'app', 'domain']
        read_only_fields = ['uuid']

    def validate_domain(self, value):
        """
        Check that the hostname is valid
        """
        if value[-1:] == ".":
            value = value[:-1]  # strip exactly one dot from the right, if present

        if value == "*":
            raise serializers.ValidationError("Hostname can't only be a wildcard")

        labels = value.split('.')

        # Let wildcards through by not trying to validate it
        wildcard = True if labels[0] == '*' else False
        if wildcard:
            labels.pop(0)

        try:
            # IDN domain labels to ACE (IDNA2008)
            def ToACE(x): return idna.alabel(x).decode("utf-8", "strict")
            labels = list(map(ToACE, labels))
        except idna.IDNAError as e:
            raise serializers.ValidationError(
               "Hostname does not look valid, could not convert to ACE {}: {}"
               .format(value, e))

        # TLD must not only contain digits according to RFC 3696
        if labels[-1].isdigit():
            raise serializers.ValidationError('Hostname does not look valid.')

        # prepend wildcard 'label' again if removed before
        if wildcard:
            labels.insert(0, '*')

        # recreate value using ACE'd labels
        aceValue = '.'.join(labels)

        if len(aceValue) > 253:
            raise serializers.ValidationError('Hostname must be 253 characters or less.')

        if models.Domain.objects.filter(domain=aceValue).exists():
            raise serializers.ValidationError(
               "The domain {} is already in use by another app".format(value))

        return aceValue


class CertificateSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.Cert` model."""

    owner = serializers.ReadOnlyField(source='owner.username')
    domains = serializers.ReadOnlyField()
    san = serializers.ListField(
        child=serializers.CharField(allow_blank=True, allow_null=True, required=False),
        required=False
    )

    class Meta:
        """Metadata options for CertificateSerializer."""
        model = models.Certificate
        extra_kwargs = {
            'certificate': {'write_only': True},
            'key': {'write_only': True}
        }
        read_only_fields = ['common_name', 'fingerprint', 'san', 'domains', 'subject', 'issuer']
        fields = '__all__'


class PodSerializer(serializers.BaseSerializer):
    name = serializers.CharField()
    state = serializers.CharField()
    type = serializers.CharField()
    release = serializers.CharField()
    started = serializers.DateTimeField()

    def to_representation(self, obj):
        return obj


class AppSettingsSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.AppSettings` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    autoscale = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)
    label = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`AppSettingsSerializer`."""
        model = models.AppSettings
        fields = '__all__'

    def validate_whitelist(self, data):
        for address in data:
            try:
                ipaddress.ip_address(address)
            except:
                try:
                    ipaddress.ip_network(address)
                except:
                    try:
                        ipaddress.ip_interface(address)
                    except:
                        raise serializers.ValidationError(
                           "The address {} is not valid".format(address))

        return data

    def validate_autoscale(self, data):
        schema = {
            "$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {
                # minimum replicas autoscale will keep resource at based on load
                "min": {"type": "integer"},
                # maximum replicas autoscale will keep resource at based on load
                "max": {"type": "integer"},
                # how much CPU load there is to trigger scaling rules
                "cpu_percent": {"type": "integer"},
            },
            "required": ["min", "max", "cpu_percent"],
        }

        for proc, autoscale in data.items():
            if autoscale is None:
                continue

            try:
                jsonschema.validate(autoscale, schema)
            except jsonschema.ValidationError as e:
                raise serializers.ValidationError(
                    "could not validate {}: {}".format(autoscale, e.message)
                )

        return data


class TLSSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.TLS` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`AppSettingsSerializer`."""
        model = models.TLS
        fields = '__all__'
