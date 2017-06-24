from hashlib import sha256
from urllib.parse import urlparse
from furl import furl

class DomainSigner():
    
    def __init__(self, private_key, query_key ='signature'):
        self.__private_key = private_key
        self.__query_key = query_key

    def get_signed_uri(self, uri):
    
        domain_signature = self.__generate_domain_signature(uri)
        signed_uri = self.__add_signature_to_uri(uri, domain_signature)
        
        return signed_uri
    
    def verify_domain_signature(self, uri):

        uri_signature = furl(uri).args[self.__query_key]
        domain_signature = self.__generate_domain_signature(uri)
            
        return uri_signature == domain_signature
    
    def __generate_domain_signature(self, uri):
   
        parsed_url = urlparse(uri)
        domain = parsed_url.netloc or parsed_url.path
        sha256_hash = sha256()
        sha256_hash.update(domain.encode('utf-8'))
        sha256_hash.update(self.__private_key.encode('utf-8'))

        return sha256_hash.hexdigest()

    def __add_signature_to_uri(self, uri, signature):
    
        furl_object = furl(uri)
        furl_object.add(args={self.__query_key: signature})
    
        return str(furl_object.url)
