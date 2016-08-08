import unittest
from scheduler.states import PodState


class TestSchedulerStates(unittest.TestCase):
    """Test Scheduler States OrderedEnum"""

    def test_gt_comparison(self):
        self.assertTrue(PodState.up > PodState.starting)
        self.assertFalse(PodState.starting > PodState.up)
        with self.assertRaises(TypeError):
            self.assertTrue(PodState.up > 'starting')

    def test_ge_comparison(self):
        self.assertTrue(PodState.up >= PodState.starting)
        self.assertFalse(PodState.starting >= PodState.up)
        with self.assertRaises(TypeError):
            self.assertTrue(PodState.up >= 'starting')

    def test_lt_comparison(self):
        self.assertFalse(PodState.up < PodState.starting)
        self.assertTrue(PodState.starting < PodState.up)
        with self.assertRaises(TypeError):
            self.assertTrue(PodState.up < 'crashed')

    def test_le_comparison(self):
        self.assertFalse(PodState.up <= PodState.starting)
        self.assertTrue(PodState.starting <= PodState.up)
        with self.assertRaises(TypeError):
            self.assertTrue(PodState.up <= 'crashed')

    def test_str(self):
        self.assertEqual(str(PodState.up), 'up')
