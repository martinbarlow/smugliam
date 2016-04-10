import requests

import pprint
import json
from rauth import OAuth1Service
from rauth import OAuth1Session
import sys
import urlparse
import urllib


def main():
    smugmug = Smugmug(config_file='config.json', token_file='token.json')
    
#    rt, rts = service.get_request_token(params={'oauth_callback': 'oob'})
#    auth_url = add_auth_params(
#            service.get_authorize_url(rt), access='Full', permissions='Modify')
#    print('Go to %s in a web browser.' % auth_url)

#    sys.stdout.write('Enter the six-digit code: ')
#    sys.stdout.flush()
#    verifier = sys.stdin.readline().strip()
#    at, ats = service.get_access_token(rt, rts, params={'oauth_verifier': verifier})
#    print('Access token: %s' % at)
#    print('Access token secret: %s' % ats)

    pprint.pprint(smugmug.get_user('variar').text)

class Smugmug(object):

    OAUTH_ORIGIN = 'https://secure.smugmug.com'
    REQUEST_TOKEN_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/getRequestToken'
    ACCESS_TOKEN_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/getAccessToken'
    AUTHORIZE_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/authorize'

    API_ORIGIN = 'https://api.smugmug.com'


    def __init__(self, config_file=None, token_file=None):
        if config_file is None:
            raise TypeError('config_file must be defined')
        if token_file is None:
            raise TypeError('token_file must be defined')
        self.config_file = config_file
        self.token_file = token_file

    def get_user(self, nickname):
        headers = {'Accept': 'application/json'}
        session = self._get_session()
        return session.get(headers=headers, url = self._url('user/{0}'.format(nickname)))

    def _url(self, path):
        return self.API_ORIGIN + '/api/v2/' + path

    def _get_session(self):
        try:
            return self.session
        except AttributeError:
            at, ats = self._get_token()
            service = self._get_service()
            session = OAuth1Session(
                    service.consumer_key,
                    service.consumer_secret,
                    access_token=at,
                    access_token_secret=ats)
            self.session = session
            return self.session


    def _get_service(self):
        try:
            return self.service
        except AttributeError:
            with open(self.config_file, 'r') as fh:
                config = json.load(fh)
            if type(config) is not dict \
                    or 'key' not in config \
                    or 'secret' not in config:
                raise TypeError('Invalid Config file: {0}'.format(config_file))
            service = OAuth1Service(
                    name='smugliam',
                    consumer_key=config['key'],
                    consumer_secret=config['secret'],
                    request_token_url=self.REQUEST_TOKEN_URL,
                    access_token_url=self.ACCESS_TOKEN_URL,
                    authorize_url=self.AUTHORIZE_URL,
                    base_url=self.API_ORIGIN + '/api/v2')
            self.service = service
            return self.service 

    def _get_token(self):
        try:
            return (self.token, self.token_secret)
        except AttributeError:
            with open(self.token_file, 'r') as fh:
                config = json.load(fh)
            if type(config) is not dict \
                or 'key' not in config \
                or 'secret' not in config:
                    raise TypeError('Invalid Config file: {0}'.format(config_file))
            self.token = config['key']
            self.token_secret = config['secret']
            return (self.token, self.token_secret)

    def add_auth_params(auth_url, access=None, permissions=None):
        if access is None and permissions is None:
            return auth_url
        parts = urlparse.urlsplit(auth_url)
        query = urlparse.parse_qsl(parts.query, True)
        if access is not None:
            query.append(('Access', access))
        if permissions is not None:
            query.append(('Permissions', permissions))
        return urlparse.urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path,
            urllib.urlencode(query, True),
            parts.fragment))

if __name__ == '__main__':
    main()
