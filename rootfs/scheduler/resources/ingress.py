from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class Ingress(Resource):
    short_name = 'ingress'

    def get(self, name=None, **kwargs):
        """
        Fetch a single Ingress or a list of Ingresses
        """
        if name is not None:
            url = "/apis/extensions/v1beta1/namespaces/%s/ingresses/%s" % (name, name)
            message = 'get Ingress ' + name
        else:
            url = "/apis/extensions/v1beta1/namespaces/%s/ingresses" % name
            message = 'get Ingresses'

        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, ingress, namespace, hostname):
        url = "/apis/extensions/v1beta1/namespaces/%s/ingresses" % namespace

        data = {
            "kind": "Ingress",
            "apiVersion": "extensions/v1beta1",
            "metadata": {
                "name": ingress
            },
            "spec": {
                "rules": [
                    {"host": ingress + "." + hostname,
                     "http": {
                         "paths": [
                             {"path": "/",
                              "backend": {
                                  "serviceName": ingress,
                                  "servicePort": 80
                              }}
                         ]
                     }
                     }
                ]
            }
        }
        response = self.http_post(url, json=data)

        if not response.status_code == 201:
            raise KubeHTTPException(response, "create Ingress {}".format(namespace))

        return response

    def delete(self, namespace, ingress):
        url = "/apis/extensions/v1beta1/namespaces/%s/ingresses/%s" % (namespace, ingress)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete Ingress "{}"', namespace)

        return response
