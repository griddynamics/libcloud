# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" OpenStack driver """

import urlparse
import httplib
try:
    import simplejson as json
except ImportError:
    import json
import re

from libcloud.common.types import MalformedResponseError, InvalidCredsError
from libcloud.compute.types import NodeState, Provider
from libcloud.compute.base import Node, NodeLocation
from libcloud.compute.base import NodeSize, NodeImage
from libcloud.compute.keystone import KeystoneAuth
from libcloud.compute.drivers.rackspace import MossoBasedNodeDriver, RackspaceNodeDriver
from libcloud.compute.drivers.rackspace import MossoBasedResponse, RackspaceConnection
from libcloud.compute.drivers.rackspace import MossoBasedConnection


image_id_pattern = re.compile(r'.*/images/(\d+)$')

class OpenStackJsonResponse(MossoBasedResponse):
    """ OpenStack specific response """

    def parse_body(self):
        if not self.body:
            return None
        if self.status in (202, 204):
            return self.body
        try:
            body = json.loads(self.body)
        except:
            raise MalformedResponseError("Failed to parse JSON",
                                         body=self.body,
                                         driver=OpenStackNodeDriver_v1_1)
        return body

    def parse_error(self):
        """Used in to form message for exception to raise in case self.status is not OK"""
        first_level_key = ''
        try:
            body = json.loads(self.body)
            if len(body) > 0:
                for key in body:
                    if 'message' in body[key]:
                        first_level_key = key
                        msg = body[key]['message']
                        break
            else:
                msg = self.body
        except:
            msg = self.body
        return self.error, self.status, first_level_key, msg


def OpenStackNodeDriver(version, username, api_key, secure=None, auth_host=None,
                        auth_port=None, version_url=None, keystone_url=None):
    """ A helper function to instantiate driver of desired type, depending on which openstack
    API version is used

    version - which API version to use, set to v1.0 to use older RackSpace based xml API. Set to v1.1+
              to use newer JSON-based API. If None Version API is requested and CURRENT is used.
    username - user name
    api_key - API access api key
    secure - is for v1.0 only, if connection SSL, in 1.keystone_url1 it is determined with auth info
    auth_host and auth_port - hostname and port of auth URL for 1.0 only
    version_url - For 1.1+ only. URL of version list API call
    keystone - is KeyStone authentication used
    """
    if version == 'v1.0':
        return OpenStackNodeDriver_v1_0(username, api_key, secure, host=auth_host, port=auth_port)
    else:
        if keystone_url:
            class _(KeystoneAuth, OpenStackNodeDriver_v1_1):
                def __init__(self, *arg, **kwarg):
                    KeystoneAuth.__init__(self, keystone_url=keystone_url, api_url=version_url)
                    OpenStackNodeDriver_v1_1.__init__(self, *arg, **kwarg)
            driver_class = _
        else:
            driver_class = OpenStackNodeDriver_v1_1

        if isinstance(version, dict):
            return driver_class(username, api_key, url=version_url,
                                version=version['version'], version_code_name=version['version_code_name'])
        return driver_class(username, api_key, url=version_url, version=version)



class OpenStackConnection_v1_0(RackspaceConnection):

    def __init__(self, user_id, key, secure, host, port):
        super(OpenStackConnection_v1_0, self).__init__(user_id, key, secure=secure)
        self.auth_host = host
        self.port = (port, port)

class OpenStackNodeDriver_v1_0(RackspaceNodeDriver):
    name = 'OpenStack'
    connectionCls = OpenStackConnection_v1_0

class OpenStackConnection_v1_1(MossoBasedConnection):
    """ Connection class for the OpenStack driver """

    responseCls = OpenStackJsonResponse

    def __init__(self, user_name, api_key, url, secure, version=None):
        auth_endpoint, self.version = self._request_auth_endpoint(url, version)

        auth_endpoint = urlparse.urlparse(auth_endpoint)
        auth_host = auth_endpoint.hostname
        auth_port = auth_endpoint.port
        auth_path = auth_endpoint.path

        secure = auth_endpoint.scheme == 'https'

        super(OpenStackConnection_v1_1, self).__init__(user_name, api_key, auth_host, secure, auth_port, auth_path)

    def _request_auth_endpoint(self, url, version):
        conn = None
        try:
            endpoint = urlparse.urlparse(url)

            conn = self.conn_classes[endpoint.scheme == 'https'](endpoint.hostname, endpoint.port)
            conn.request(method='GET', url=endpoint.path, headers={'Accept': 'application/json'})

            response = self.responseCls(conn.getresponse())

            body = response.parse_body()

            # currently API version is described as
            #    {"status": "CURRENT", "id": "v1.1", "links": [{"href": "http://localhost:8774/v1.1", "rel": "self"}]}
            for api in body['versions']:
                if not version and api['status'] == 'CURRENT' or api['id'] == version:
                    return api['links'][0]['href'], api['id']

            raise Exception('No openstack API version %s at %s' % (version, url))
#        except AttributeError:
#            raise MalformedResponseError('Malformed version response %s', body)
        finally:
            if conn:
                conn.close()

    def _parse_url_headers(self, headers):
        try:
            server_url = headers['x-server-management-url']

            #due to bug in openstack it always redirect to v1.0
            self.server_url = server_url.replace('v1.1', self.version)

            self.auth_token = headers['x-auth-token']
        except KeyError, e:
            # Returned 204 but has missing information in the header, something is wrong
            raise MalformedResponseError('Malformed response',
                                         body='Missing header: %s' % (str(e)),
                                         driver=self.driver)


    def _set_additional_headers(self, action, method, params, headers, data):
        if method in ("POST", "PUT"):
            headers['Content-Type'] = 'application/json'

    def add_default_headers(self, headers):
        headers['X-Auth-Token'] = self.auth_token
        headers['Accept'] = 'application/json'
        return headers

class FloatingIp():
    def __init__(self, floating_id, floating_ip, fixed_ip=None, instance_id=None):
        self.floating_id = floating_id
        self.floating_ip = floating_ip
        self.fixed_ip = fixed_ip
        self.instance_id = instance_id

    def __repr__(self):
        return 'FloatingIp: id=%s; ip=%s; fixed_ip=%s; instance_id=%s' \
        % (self.floating_id, self.floating_ip, self.fixed_ip, self.instance_id)


class OpenStackNodeDriver_v1_1(MossoBasedNodeDriver):
    """ OpenStack node driver. """
    connectionCls = OpenStackConnection_v1_1

    def _auth(self):
        """ OpenStack needs first to get an authentication token """
        
        self.connection.request(
            method='GET',
            url=self.api_version,
            headers={'X-Auth-User': self.user_id, 'X-Auth-Key': self.key}
        )

        resp = self.connection.getresponse()

        if resp.status != httplib.NO_CONTENT:
            raise InvalidCredsError()

        headers = dict(resp.getheaders())

        try:
            self.server_url = headers['x-server-management-url']
            self.auth_token = headers['x-auth-token']
        except KeyError:
            raise InvalidCredsError()


    name = 'OpenStack'
    type = Provider.OPENSTACK

    features = {"create_node": ["generates_password"]}

    NODE_STATE_MAP = { 'BUILD': NodeState.PENDING,
                       'REBUILD': NodeState.PENDING,
                       'ACTIVE': NodeState.RUNNING,
                       'SUSPENDED': NodeState.TERMINATED,
                       'QUEUE_RESIZE': NodeState.PENDING,
                       'PREP_RESIZE': NodeState.PENDING,
                       'VERIFY_RESIZE': NodeState.RUNNING,
                       'PASSWORD': NodeState.PENDING,
                       'RESIZE': NodeState.PENDING,
                       'RESCUE': NodeState.PENDING,
                       'REBOOT': NodeState.REBOOTING,
                       'HARD_REBOOT': NodeState.REBOOTING,
                       'DELETE_IP': NodeState.PENDING,
                       'UNKNOWN': NodeState.UNKNOWN}

    def __init__(self, user_name, api_key, url, secure=False, version=None, version_code_name=None):
        """
        user_name NOVA_USERNAME as reported by OpenStack
        api_key NOVA_API_KEY as reported by OpenStack
        url NOVA_URL as reported by OpenStack.
        secure use HTTPS or HTTP. Note: currently only HTTP
        version - which API version to use
        """

        self.connection = self.connectionCls(user_name=user_name,
                                             api_key=api_key,
                                             url=url,
                                             secure=secure,
                                             version=version)
        self.connection.driver = self
        self.connection.connect()
        self.version_code_name=version_code_name

    def list_locations(self):
        """Lists available locations. So far there is no public locations
        so we return fake location
        """

        return [NodeLocation(id=0, name='OpenStack is private cloud',
                             country='NoCountry', driver=self)]

    def ex_list_flavors(self):
        self.list_sizes()

    def _to_sizes(self, flavors_dict):
        try:
            flavors = flavors_dict['flavors']
        except KeyError:
            raise MalformedResponseError(value='no flavors-values clause',
                                         body=flavors_dict, driver=self)
        return [ self._to_size(value) for value in flavors ]

    def _to_size(self, el):
        s = OpenstackNodeSize(id=el.get('id'),
                     ram=int(el.get('ram')),
                     disk=int(el.get('disk')),
                     name=el.get('name'),
                     price=None,
                     bandwidth=None,
                     driver=self.connection.driver,
                     links=el.get('links'))
        return s
    
    def _to_images(self, images_dict):
        try:
            images = images_dict['images']
        except KeyError:
            raise MalformedResponseError(value='no images clause',
                                         body=images_dict, driver=self)
        #filter out all inactive images, since there's no way to tell client image is not ok
        return [ self._to_image(image)
                 for image in images if image.get('status') == 'ACTIVE' ]

    def _to_image(self, el):
        if 'image' in el:
            el = el.get('image')

        image = NodeImage(id=el.get('id'),
                          name=el.get('name'),
                          driver=self.connection.driver,
                          extra={'updated': el.get('updated'),
                                 'links': el.get('links'),
                                 'status': el.get('status')}
        )
        return image

    def _to_nodes(self, servers_dict):
        try:
            servers = servers_dict['servers']
        except KeyError:
            raise MalformedResponseError(value='no servers-values clause',
                                         body=servers_dict, driver=self)
        return [ self._to_node(server) for server in servers ]

    def ex_list_servers(self):
        self.list_nodes()

    def create_node(self, **kwargs):
        """Create a new node

        See L{NodeDriver.create_node} for more keyword args, some of them:
            ex_metadata: dict of Key/Value metadata to associate with a node
            ex_files: dict {filename: content} to be injected to VM
        """
        name = kwargs['name']
        node_image = kwargs['image']
        node_size = kwargs['size']
        ex_metadata = kwargs.get('ex_metadata')
        ex_personality = kwargs.get('ex_personality')

        imageRef = node_image.extra['links'][0]['href']
        flavorRef = node_size.links[0]['href']
        
        if self.version_code_name == 'D2':
            imageRef = str(node_image.id)
            flavorRef = str(node_size.id)

        request = {'server': {'name': name, 'flavorRef': flavorRef,
                              'imageRef': imageRef}}
        if ex_metadata:
            request['server']['metadata'] = ex_metadata
        if ex_personality:
            request['server']['personality'] = ex_personality

        data = json.dumps(request)
        resp = self.connection.request("/servers", method='POST', data=data)
        try:
            server_dict = resp.object['server']
        except KeyError:
            raise MalformedResponseError(value='no server clause',
                                         body=resp.object, driver=self)
        return self._to_node(server_dict=server_dict)

    def _to_node(self, server_dict):
        """ Here we expect a dictionary which is under the clause server
        or servers in /servers or /servers/detail
        """

        if 'server' in server_dict:
            server_dict = server_dict['server']

        ips = OpenStackIps(server_dict['addresses'])

        n = Node(id=server_dict.get('id'),
                 name=server_dict.get('name'),
                 state=self.NODE_STATE_MAP.get(server_dict.get('status'),
                                               NodeState.UNKNOWN),
                 public_ip=ips.public_ipv4, #list of addresses
                 private_ip=ips.private_ipv4, #list of addresses
                 driver=self.connection.driver,
                 extra={
                    'adminPass': server_dict.get('adminPass'),
                    'affinityId': server_dict.get('affinityId'),
                    'created': server_dict.get('created'),
                    'flavorRef': server_dict.get('flavorRef'),
                    'hostId': server_dict.get('hostId'),
                    'id': server_dict.get('id'),
                    'imageRef': server_dict.get('imageRef'),
                    'links':  server_dict.get('links'),
                    'metadata': server_dict.get('metadata'),
                    'progress': server_dict.get('progress')
                 })
        return n

    def ex_rebuild(self, node_id, image_ref):
        body = {"rebuild" : {"imageRef" : image_ref}}
        resp = self._node_action(node_id, body=body)
        return resp.status == 202

    def ex_get_image_details(self, image_id):
        return self._to_image(self.connection.request('/images/%s' % image_id).object)

    def ex_get_size_details(self, size_id):
        return self._to_size(self.connection.request('/flavors/%s' % size_id).object)

    def _node_action(self, node, body):
        return super(OpenStackNodeDriver_v1_1, self)._node_action(node,
                                                                  json.dumps(body))

    def ex_limits(self):
        resp = self.connection.request('/limits', method='GET')
        return resp.object['limits']

    def _to_floating_ip(self, floating_ip):
        return FloatingIp(floating_ip['id'], floating_ip['ip'], floating_ip['fixed_ip'], floating_ip['instance_id'])

    def ex_allocate_floating_ip(self):
        resp = self.connection.request('/os-floating-ips', method='POST')
        return FloatingIp(resp.object['allocated']['id'], resp.object['allocated']['floating_ip'])

    def ex_release_floating_ip(self, floating_ip_id):
        resp = self.connection.request('/extras/os-floating-ips/%s' %floating_ip_id, method='DELETE')
        return resp.status == 200

    def ex_get_all_floating_ips(self):
        resp = self.connection.request('/os-floating-ips')
        return map(lambda x: self._to_floating_ip(x['floating_ip']), resp.object['floating_ips'])

    def ex_associate_floating_ip(self, floating_ip_id, fixed_ip_id, server_id):
        request = {'associate_address' :{'fixed_ip' : fixed_ip_id}, "instance_id": server_id}
        resp = self.connection.request('/extras/os-floating-ips/%s/associate' % floating_ip_id,
                                       method='POST', data=json.dumps(request))
        return resp.status == 200

    def ex_floating_ip_details(self, floating_ip_id):
        resp = self.connection.request('/os-floating-ips/%s' % floating_ip_id)
        return  self._to_floating_ip(resp.object['floating_ip'])

    def ex_disassociate_floating_ip(self, floating_ip_id):
        resp = self.connection.request('/extras/os-floating-ips/%s/disassociate' % floating_ip_id, method='POST')
        return resp.status == 200

    def ex_reboot(self, node, reboot_type):
        body = {"reboot" : {"type": reboot_type}}
        resp = self._node_action(node, body=body)
        return resp.status == 202

    def ex_save_image(self, node, name):
        body = {"createImage": {"name": name}}
        resp = self._node_action(node, body=body)
        if resp.status != 202:
            return None
        location = resp.headers['location']
        m = image_id_pattern.match(location)
        if not m:
            return None
        return m.group(1)

    def ex_destroy_image(self, image):
        if isinstance(image, basestring) or isinstance(image, int):
            image_id = image
        else:
            image_id = image.id
        resp = self.connection.request('/images/%s' % image_id, method='DELETE')
        return resp.status == 204


class OpenStackIps(object):
    """ Contains the list of public and private IPs """

    def __init__(self, ip_list):
        self.public_ipv4 = []
        self.private_ipv4 = []
        self.public_ipv6 = []
        self.private_ipv6 = []
        if 'public' in ip_list:
            self._separate_by_protocol(ip_list['public'],
                                       self.public_ipv4, self.public_ipv6)
        if 'private' in ip_list:
            self._separate_by_protocol(ip_list['private'],
                                       self.private_ipv4, self.private_ipv6)

    def _separate_by_protocol(self, input_list, out_list_v4, out_list_v6):
        """
        convert IP dictionary to list of the structure,
        note that out_list_v4 and out_list_v6 are modified
        """

        for ip in input_list:
            if ip['version'] == 4:
                out_list_v4.append(ip['addr'])
            if ip['version'] == 6:
                out_list_v6.append(ip['addr'])


class OpenstackNodeSize(NodeSize):
    """ extends base NodeSize with links section """
    links = []
    def __init__(self, id, name, ram, disk, bandwidth, price, driver, links):
        super(OpenstackNodeSize, self).__init__(id, name, ram, disk,
                                                bandwidth, price, driver)
        self.links = links
