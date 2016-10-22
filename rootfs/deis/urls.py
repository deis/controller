"""
URL routing patterns for the Deis project.

This is the "master" urls.py which then includes the urls.py files of
installed apps.
"""


from django.conf.urls import include, url
from api.views import LivenessCheckView, ReadinessCheckView, schema_view

urlpatterns = [
    url('^$', schema_view),
    url(r'^healthz$', LivenessCheckView.as_view()),
    url(r'^readiness$', ReadinessCheckView.as_view()),
    url(r'^v2/', include('api.urls')),
]
