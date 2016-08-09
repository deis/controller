import unittest
from scheduler import utils


class TestUtils(unittest.TestCase):
    """Test utils functions"""
    def test_dict_merge_not_dict(self):
        """
        second item is not a dict, which dict_merge will just return
        """
        a = {'key': 'value'}
        b = 'somethig'
        c = utils.dict_merge(a, b)
        self.assertEqual(c, b)

    def test_dict_merge_simple(self):
        a = {'key': 'value'}
        b = {'key': 'value'}

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {'key': 'value'})

        a = {'key': 'value'}
        b = {'key2': 'value'}

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {'key': 'value', 'key2': 'value'})

    def test_dict_merge_deeper(self):
        a = {'key': 'value', 'here': {'without': 'you'}}
        b = {'this': 'that', 'here': {'with': 'me'}, 'other': {'magic', 'unicorn'}}

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {
            'key': 'value',
            'this': 'that',
            'here': {
                'with': 'me',
                'without': 'you'
            },
            'other': {'magic', 'unicorn'}
        })

    def test_dict_merge_even_deeper(self):
        a = {
            'key': 'value',
            'here': {'without': 'you'},
            'other': {'scrubs': {'char3': 'Cox'}}

        }

        b = {
            'this': 'that',
            'here': {'with': 'me'},
            'other': {'magic': 'unicorn', 'scrubs': {'char1': 'JD', 'char2': 'Turk'}}
        }

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {
            'key': 'value',
            'this': 'that',
            'here': {'with': 'me', 'without': 'you'},
            'other': {
                'magic': 'unicorn',
                'scrubs': {
                    'char1': 'JD',
                    'char2': 'Turk',
                    'char3': 'Cox'
                }
            }
        })

    def test_dict_merge_with_list(self):
        a = {'key': 'value', 'names': ['bob', 'kyle', 'kenny', 'jimbo']}
        b = {'key': 'value', 'names': ['kenny', 'cartman', 'stan']}

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {'key': 'value', 'names': ['bob', 'kyle', 'kenny',
                                                       'jimbo', 'cartman', 'stan']})

        a = {'key': 'value', 'names': ['bob', 'kyle', 'kenny', 'jimbo']}
        b = {'key': 'value', 'last_names': ['kenny', 'cartman', 'stan']}

        c = utils.dict_merge(a, b)
        self.assertEqual(c, {'key': 'value',
                             'names': ['bob', 'kyle', 'kenny', 'jimbo'],
                             'last_names': ['kenny', 'cartman', 'stan']})

    def test_dict_merge_bad_merge(self):
        """Returns b because it isn't a dict"""
        a = {'key': 'value'}
        b = 'duh'

        c = utils.dict_merge(a, b)
        self.assertEqual(c, b)
