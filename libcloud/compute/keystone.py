import urllib
import urlparse

try:
    import simplejson as json
except ImportError:
    import json

class KeystoneAuth(object):

    def __init__(self, keystone_url, api_url ):
        self.keystone_url = keystone_url
        connectionCls = self.connectionCls
        class _ (KeystoneConnection, connectionCls):
            def __init__(self, *args, **kwargs):
                KeystoneConnection.__init__(self, keystone_url, api_url)
                connectionCls.__init__(self, *args, **kwargs)
        self.connectionCls = _

class KeystoneConnection(object):
    def __init__(self, keystone_url, api_url):
        self.keystone_url = keystone_url
        self.api_url = api_url

    def _request_auth_endpoint(self, url, version):
        return (url, version)

    def _auth(self):

        endpoint = urlparse.urlparse(self.keystone_url)

        headers={
            'X-Auth-User': self.user_id,
            'X-Auth-Key': self.key
        }

        while True:
            conn = self.conn_classes[endpoint.scheme == 'https'](endpoint.hostname, endpoint.port)
            body = json.dumps({"passwordCredentials":{"username": self.user_id,
                                                      "password": self.key,
                                                      "tenantId": self.user_id}})
            conn.request(method='POST',
                         url=endpoint.path,
                         headers={'Accept': 'application/json',
                                  'Content-Type': 'application/json'},
                         body=body)

            resp = conn.getresponse()

            if resp.status == 200 or resp.status == 204:
                body = resp.read()
                body = json.loads(body)

                self.server_url = self.api_url
                #body['auth']['serviceCatalog']['nova'][0]['adminURL']
                self.auth_token = body['auth']['token']['id']
                for key in ['server_url', 'storage_url', 'cdn_management_url',
                            'lb_url']:
                    url = getattr(self, key, None)
                    if url:
                        scheme, server, request_path, param, query, fragment = (
                            urlparse.urlparse(getattr(self, key)))
                        # Set host to where we want to make further requests to
                        setattr(self, '__%s' % (key), server)
                        setattr(self, '__request_path_%s' % (key), request_path)
                return
            elif resp.status == 305:
                redir_location = headers['location']
                redir_type, redir_hostname, auth_port, _ = self._split_in_parts(redir_location)
                auth_port = int(auth_port)
                if redir_hostname.startswith('127') or redir_hostname == 'localhost':
                    redir_hostname = auth_hostname
            else:
                raise Exception("auth failed responce %s " % str(resp.status) )

    @staticmethod
    def _split_in_parts(url):
        type_, urlpath = urllib.splittype(url)
        host, path = urllib.splithost(urlpath)
        hostname, port = urllib.splitport(host)
        return type_, hostname, port, path

