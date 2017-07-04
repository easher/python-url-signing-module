import sys
from os.path import realpath
sys.path.insert(0, '../src/')

import unittest
from ddt import ddt, data

from UrlSigner import UrlSigner

@ddt
class UrlSignerTest(unittest.TestCase):
    
    def setUp(self):
        
        self.secret_key = "super_secret_test_key"
        self.query_key = "signature_param"
        self.url_signer = UrlSigner(self.secret_key)
    
    @data (
            # web domain doesn't match signaturee
            ("https://www.reddit.com?signature=7c72fbc912121a00ce8a684e6941cc81", True),
            ("https://www.facebook.com?signature=7c72fbc912121a00ce8a684e6941cc81", False),
            
            #  sub reddit doesn't match signature
            ("https://www.reddit.com/r/foo?signature=d85968ba815755dfd91b0594255ec6b2", True),
            ("https://www.reddit.com/r/notfoo?signature=d85968ba815755dfd91b0594255ec6b2", False),
            
            # query string doesn't match signature
            ("https://reddit.com?greetings=hello&signature=6a017725e5d5d97c5435cc20bade1c64", True),
            ("https://reddit.com?greetings=goodby&signature=6a017725e5d5d97c5435cc20bade1c64",False),
            
            # bad signature
            ("https://reddit.com?greetings=hello&signature=6a017725e5d5d97cdfdfdasfdaae1c64", False)
        )
 
    def test_validate_url_signatures(self, test_data):
        
        url, is_valid_signature = test_data
        self.assertEqual(is_valid_signature, self.url_signer.verify_url_signature(url))
        

if __name__ == '__main__':
    unittest.main()
