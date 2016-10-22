import unittest
from scheduler.resources.pod import Pod


class TestSchedulerPodResources(unittest.TestCase):
    def test_manifest_limits(self):
        cpu_cases = [
            {"app_type": "web", "cpu": {"cmd": "2"},
             "expected": None},
            {"app_type": "web", "cpu": {"web": "2"},
             "expected": {"limits": {"cpu": "2"}}},
            {"app_type": "web", "cpu": {"web": "0/3"},
             "expected": {"requests": {"cpu": "0"}, "limits": {"cpu": "3"}}},
            {"app_type": "web", "cpu": {"web": "4/5"},
             "expected": {"requests": {"cpu": "4"}, "limits": {"cpu": "5"}}},
            {"app_type": "web", "cpu": {"web": "400m/500m"},
             "expected": {"requests": {"cpu": "400m"}, "limits": {"cpu": "500m"}}},
            {"app_type": "web", "cpu": {"web": "0.6/0.7"},
             "expected": {"requests": {"cpu": "0.6"}, "limits": {"cpu": "0.7"}}},
        ]

        mem_cases = [
            {"app_type": "web", "memory": {"cmd": "2G"},
             "expected": None},
            {"app_type": "web", "memory": {"web": "200M"},
             "expected": {"limits": {"memory": "200Mi"}}},
            {"app_type": "web", "memory": {"web": "0/3G"},
             "expected": {"requests": {"memory": "0"}, "limits": {"memory": "3Gi"}}},
            {"app_type": "web", "memory": {"web": "400M/500MB"},
             "expected": {"requests": {"memory": "400Mi"}, "limits": {"memory": "500Mi"}}},
        ]

        for caze in cpu_cases:
            manifest = Pod("").manifest("",
                                        "",
                                        "",
                                        app_type=caze["app_type"],
                                        cpu=caze["cpu"])
            self._assert_resources(caze, manifest)

        for caze in mem_cases:
            manifest = Pod("").manifest("",
                                        "",
                                        "",
                                        app_type=caze["app_type"],
                                        memory=caze["memory"])
            self._assert_resources(caze, manifest)

    def _assert_resources(self, caze, manifest):
        resources_parent = manifest["spec"]["containers"][0]
        expected = caze["expected"]
        if expected:
            self.assertEqual(resources_parent["resources"], expected, caze)
        else:
            self.assertTrue("resources" not in resources_parent, caze)
