import hashlib
from furl import furl
from codecs import encode
import hmac

class UrlSigner():
    
    def __init__(self, private_key, signature_key = 'signature'):
        
        self.__private_key = private_key
        self.__signature_key = signature_key

    def get_signed_url(self, url):
    
        url_signature = self.__generate_url_signature(url)
        signed_url = self.__add_signature_to_url(url, url_signature)        
        
        return signed_url
    
    def verify_url_signature(self, url):

        url_parser = furl(url)
        hash_helper = self.__get_hmac()

        url_signature = url_parser.args[self.__signature_key]
        url_without_signature = url_parser.remove(self.__signature_key).url
        
        signature_using_private_key  = self.__generate_url_signature(url_without_signature)
        
        return hmac.compare_digest(url_signature, signature_using_private_key)
    
    def __generate_url_signature(self, url):
   
        hash_helper = self.__get_hmac()
        hash_helper.update(url.encode('utf-8'))
        return hash_helper.hexdigest()

    def __add_signature_to_url(self, url, signature):
    
        furl_object = furl(url)
        furl_object.add({self.__signature_key: signature})
    
        return furl_object.url

    def __get_hmac(self):
        
        #convert key to bit array
        byte_array = bytearray()
        byte_array.extend(map(ord, self.__private_key))

        return hmac.new(byte_array, digestmod=hashlib.md5)
