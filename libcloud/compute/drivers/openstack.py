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
"""
Openstack drivers
"""
import httplib
import sys
from libcloud import enable_debug

try:
    import json
except:
    import simplejson as json

from libcloud.compute.base import NodeSize, NodeLocation, Node
from libcloud.compute.drivers.rackspace import RackspaceResponse, RackspaceNodeDriver, RackspaceConnection
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider, NodeState
from libcloud.pricing import get_size_price, PRICING_DATA
from xml.etree import ElementTree as ET
from libcloud.common.types import MalformedResponseError, InvalidCredsError

class OpenStackResponse(RackspaceResponse):
    def has_content_type(self, content_type):
        content_type_header = dict([(key, value) for key, value in
                                                 self.headers.items()
                                                 if key.lower() == 'content-type'])
        if not content_type_header:
            return False

        content_type_value = content_type_header['content-type'].lower()

        return content_type_value.find(content_type.lower()) > -1

    def parse_body(self):
        if not self.has_content_type('application/xml') or not self.body:
            return self.body

        try:
            return ET.XML(self.body)
        except:
            raise MalformedResponseError(
                'Failed to parse XML',
                body=self.body,
                driver=RackspaceNodeDriver)


class OpenStackConnection(RackspaceConnection):
    responseCls = OpenStackResponse

    def __init__(self, user_id, key, secure, host, port):
        super(OpenStackConnection, self).__init__(user_id, key, secure=secure)
        self.auth_host = host
        self.port = (port, port)
        self.server_url = None

    @property
    def host(self):
        return self.auth_host

    def connect(self, host=None, port=None):
        if not self.auth_token:
            self.server_url = 'http%s://%s:%s/%s' %\
                              ('s' if self.secure else '', self.auth_host, self.port[self.secure], self.api_version)
            self.__server_url = self.auth_host
            self.driver.auth_provider.authenticate(self)

        super(OpenStackConnection, self).connect(host, port)


class KeyStoneAuthProvider(object):
    def __init__(self, port, host=None, tenant_id=None, version='v2.0'):
        self.port = port
        self.host = host
        self.tenant_id = tenant_id
        self.version = version

    def authenticate(self, connection):
        credentials = {
            'username': connection.user_id,
            'password': connection.key
        }

        if self.tenant_id:
            credentials['tenantId'] = self.tenant_id

        # Initial connection used for authentication
        conn = connection.conn_classes[connection.secure](
            self.host or connection.host, self.port)

        try:
            conn.request(
                method='POST',
                url='/%s/tokens' % self.version,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body=json.dumps({'passwordCredentials': credentials})
            )

            self._handle_response(conn.getresponse(), connection)
        finally:
            conn.close()

    def _handle_response(self, resp, conn):
        if resp.status == httplib.OK:
            # HTTP OK (200): auth successful
            try:
                auth = json.loads(resp.read())
                conn.auth_token = auth['auth']['token']['id']
            except Exception as e:
                # Returned 200 but has missing information in the header, something is wrong
                raise MalformedResponseError('Malformed response',
                                             body='Invalid response body',
                                             driver=conn.driver)
        elif resp.status == httplib.UNAUTHORIZED:
            # HTTP UNAUTHORIZED (401): auth failed
            raise InvalidCredsError()
        else:
            # Any response code != 401 or 204, something is wrong
            raise MalformedResponseError('Malformed response',
                                         body='code: %s body:%s' % (resp.status, ''.join(resp.body.readlines())),
                                         driver=conn.driver)


class RackspaceAuthProvider(object):
    def authenticate(self, connection):
        connection._populate_hosts_and_request_paths()


class OpenStackNodeDriver(RackspaceNodeDriver):
    name = 'OpenStack'
    type = Provider.OPENSTACK
    connectionCls = OpenStackConnection

    def __init__(self, key, secret=None, secure=True, host=None, port=None, auth_provider=RackspaceAuthProvider()):
        self.auth_provider = auth_provider
        super(OpenStackNodeDriver, self).__init__(key, secret, secure, host, port)

    def _get_size_price(self, size_id):
        if 'openstack' not in PRICING_DATA['compute']:
            return 0.0

        return get_size_price(driver_type='compute',
                              driver_name='openstack',
                              size_id=size_id)


class OpenStackConnection_v1_1(OpenStackConnection):
    api_version = 'v1.1'


OPENSTACK_NAMESPACE = 'http://docs.openstack.org/compute/api/v1.1'

class FloatingIp(object):
    def __init__(self, driver, id, ip, fixed_ip=None, instance_id=None):
        self.driver = driver
        self.id = id
        self.ip = ip
        self.fixed_ip = fixed_ip
        self.instance_id = instance_id

    def associate(self, ip):
        return self.driver.ex_associate_floating_ip(self.id, ip)

    def disassociate(self):
        return self.driver.ex_disassociate_floating_ip(self.id)

    def __repr__(self):
        return (('<FloatingIp: id=%s, ip=%s, fixed_ip=%s, instance_id=%s, provider=%s>')
                % (self.id, self.ip, self.fixed_ip, self.instance_id, self.driver.name))


class OpenStackNodeDriver_v1_1(OpenStackNodeDriver):
    name = "OpenStack (API v1.1)"
    type = Provider.OPENSTACK_V1_1
    connectionCls = OpenStackConnection_v1_1

    NODE_STATE_MAP = {'BUILD': NodeState.PENDING,
                      'REBUILD': NodeState.PENDING,
                      'ACTIVE': NodeState.RUNNING,
                      'SUSPENDED': NodeState.TERMINATED,
                      'RESIZE': NodeState.PENDING,
                      'VERIFY_RESIZE': NodeState.RUNNING,
                      'PASSWORD': NodeState.PENDING,
                      'REBOOT': NodeState.REBOOTING,
                      'HARD_REBOOT': NodeState.REBOOTING,
                      'DELETED': NodeState.PENDING,
                      'ERROR': NodeState.ERROR,
                      'UNKNOWN': NodeState.UNKNOWN}

    def ex_image_details(self, image_id):
        resp = self.connection.request("/images/%s" % image_id)
        return self._to_image(resp.object)

    def ex_size_details(self, size_id):
        resp = self.connection.request("/flavors/%s" % size_id)
        return self._to_size(resp.object)

    def create_node(self, **kwargs):
        name = kwargs['name']
        image = kwargs['image']
        size = kwargs['size']

        attributes = {'xmlns': OPENSTACK_NAMESPACE,
                      'name': name,
                      'imageRef': str(image.id),
                      'flavorRef': str(size.id)
        }

        server_elm = ET.Element('server', attributes)

        metadata_elm = self._metadata_to_xml(kwargs.get("ex_metadata", {}))
        if metadata_elm:
            server_elm.append(metadata_elm)

        files_elm = self._files_to_xml(kwargs.get("ex_files", {}))
        if files_elm:
            server_elm.append(files_elm)
        resp = self.connection.request("/servers",
                                       method='POST',
                                       data=ET.tostring(server_elm))
        return self._to_node(resp.object)

    def ex_rebuild(self, node_id, image_id):
        elm = ET.Element(
            'rebuild', {
                'xmlns': OPENSTACK_NAMESPACE,
                'imageRef': str(image_id),
                }
        )
        resp = self.connection.request("/servers/%s/action" % node_id,
                                       method='POST',
                                       data=ET.tostring(elm))
        return resp.status == 202

    def _reboot_node(self, node, reboot_type='SOFT'):
        elm = ET.Element(
            'reboot',
                {'xmlns': OPENSTACK_NAMESPACE,
                 'type': reboot_type,
                 }
        )
        resp = self.connection.request("/servers/%s/action" % node.id,
                                       method='POST',
                                       data=ET.tostring(elm))

        return resp.status == 202

    def ex_set_password(self, node, password):
        attributes = {'xmlns': OPENSTACK_NAMESPACE,
                      'adminPass': password
        }

        change_password_elm = ET.Element('changePassword', attributes)

        resp = self.connection.request('/servers/%s/action' % node.id,
                                       method='POST',
                                       data=ET.tostring(change_password_elm))

        return resp.status == 202

    def ex_set_server_name(self, node, name):
        return self._ex_update_server(node.id, name=name)

    def ex_set_ipv4_address(self, node, address):
        return self._ex_update_server(node.id, accessIPv4=address)

    def ex_set_ipv6_address(self, node, address):
        return self._ex_update_server(node.id, accessIPv6=address)

    def _ex_update_server(self, node_id, **kwargs):
        attributes = {
            'xmlns': OPENSTACK_NAMESPACE
        }

        attributes.update(kwargs)

        server_elm = ET.Element('server', attributes)

        resp = self.connection.request('/servers/%s' % node_id,
                                       method='PUT',
                                       data=ET.tostring(server_elm))

        return resp.status == 204

    def _to_node(self, el):
        def get_ips(el):
            return [json.loads(ip.get('addr').replace('\'', '\"'))['addr'] for ip in el]

        #todo: test metadata support
        def get_meta_dict(el):
            d = {}
            for meta in el:
                d[meta.get('key')] = meta.text
            return d

        public_ip = get_ips(self._findall(el,
                                          'addresses/public/ip'))
        private_ip = get_ips(self._findall(el,
                                           'addresses/private/ip'))
        metadata = get_meta_dict(self._findall(el, 'metadata/meta'))

        n = Node(id=el.get('id'),
                 name=el.get('name'),
                 state=self.NODE_STATE_MAP.get(
                     el.get('status'), NodeState.UNKNOWN),
                 public_ip=public_ip,
                 private_ip=private_ip,
                 driver=self.connection.driver,
                 extra={
                     'password': el.get('adminPass'),
                     'hostId': el.get('hostId'),
                     'imageId': el.get('imageRef'),
                     'flavorId': el.get('flavorRef'),
                     'uri': self._find(el, 'links/link').get('href'),
                     'metadata': metadata,
                     })
        return n

    def _fixxpath(self, xpath):
        # ElementTree wants namespaces in its xpaths, so here we add them.
        return "/".join(["{%s}%s" % (OPENSTACK_NAMESPACE, e) for e in xpath.split("/")])

    def _find(self, el, match):
        return el.find(self._fixxpath(match))

    def _child_value(self, el, match, fix_path=True):
        element = self._find(el, match) if fix_path else el.find(match)
        return element.text.strip() if element is not None else None

    def _to_size(self, el):
        return NodeSize(id=self._child_value(el, 'id'),
                        name=self._child_value(el, 'name'),
                        ram=self._child_value(el, 'ram'),
                        disk=self._child_value(el, 'disk'),
                        bandwidth=None,
                        price=self._get_size_price(self._child_value(el, 'id')),
                        driver=self.connection.driver)

    def list_locations(self):
        return [NodeLocation(0, 'Private Cloud', 'Unknown', self)]

    def ex_limits(self):
        def _to_rate(el):
            rates = []
            for limit in self._findall(el, 'limit/item'):
                rate = {}
                for child in limit:
                    rate[child.tag.split('}')[1]] = child.text.strip()

                for item in el.items():
                    rate[item[0]] = item[1]

                rates.append(rate)

            return rates

        def _to_absolute(el):
            return {el.tag.split('}')[1]: el.text.strip()}

        limits = self.connection.request("/limits").object
        rates = []
        for el in self._findall(limits, 'rate/limit'):
            rates.extend(_to_rate(el))

        absolute = {}
        for item in self._find(limits, 'absolute'):
            absolute.update(_to_absolute(item))

        return {"rate": rates, "absolute": absolute}

    def ex_save_image(self, node, name):
        image_elm = ET.Element(
            'image',
                {
                'xmlns': OPENSTACK_NAMESPACE,
                'name': name,
                'serverRef': str(node.id)
            }
        )

        return self._to_image(self.connection.request("/images",
                                                      method="POST",
                                                      data=ET.tostring(image_elm)).object)

    def ex_delete_image(self, image_id):
        resp = self.connection.request('/images/%s' % image_id, method='DELETE')
        return resp.status == 204

    def _to_floating_ips(self, el):
        elements = el.findall('floating_ip/floating_ip')
        return [self._to_floating_ip(el) for el in elements]

    def _to_floating_ip(self, el):
        return FloatingIp(id=self._child_value(el, 'id', False),
                          ip=self._child_value(el, 'ip', False),
                          fixed_ip=self._child_value(el, 'fixed_ip', False),
                          instance_id=self._child_value(el, 'instance_id', False),
                          driver=self)

    def ex_allocate_floating_ip(self):
        resp = self.connection.request("/os-floating-ips", method='POST')

        allocated = resp.object

        return FloatingIp(id=self._child_value(allocated, 'id', False),
                          ip=self._child_value(allocated, 'floating_ip', False),
                          driver=self)

    def ex_list_floating_ips(self):
        resp = self.connection.request("/os-floating-ips")
        return self._to_floating_ips(resp.object)

    def ex_get_floating_ip_details(self, id):
        resp = self.connection.request("/os-floating-ips/%s" % id)
        return self._to_floating_ip(resp.object)

    def ex_release_floating_ip(self, id):
        resp = self.connection.request("/os-floating-ips/%s" % id, method='DELETE')
        return resp.status == 200

    def ex_associate_floating_ip(self, floating_ip_id, fixed_ip):
        fixed_ip_elm = ET.Element('fixed_ip')
        fixed_ip_elm.text = fixed_ip

        address_elm = ET.Element('associate_address')
        address_elm.append(fixed_ip_elm)

        resp = self.connection.request('/os-floating-ips/%s/associate' % floating_ip_id,
                                       method='POST',
                                       data=ET.tostring(address_elm))

        associated = resp.object

        return FloatingIp(id=self._child_value(associated, 'floating_ip_id', False),
                          ip=self._child_value(associated, 'floating_ip', False),
                          fixed_ip=self._child_value(associated, 'fixed_ip', False),
                          driver=self)

    def ex_disassociate_floating_ip(self, floating_ip_id):
        resp = self.connection.request('/os-floating-ips/%s/disassociate' % floating_ip_id,
                                       method='POST')
        return resp.status == 200

    def ex_create_ip_group(self, group_name, node_id=None):
        raise NotImplementedError("This operation is not supported")

    def ex_list_ip_groups(self, details=False):
        raise NotImplementedError("This operation is not supported")

    def ex_delete_ip_group(self, group_id):
        raise NotImplementedError("This operation is not supported")

    def ex_share_ip(self, group_id, node_id, ip, configure_node=True):
        raise NotImplementedError("This operation is not supported")

    def ex_unshare_ip(self, node_id, ip):
        raise NotImplementedError("This operation is not supported")


if __name__ == '__main__':
    NOVA_API_KEY = "54185447-b270-4223-8eb2-a8c04e9f875f"
    NOVA_USERNAME = "cloudenv"
    NOVA_HOST = "172.16.72.9"

    NOVA_API_KEY = "secrete"
    NOVA_USERNAME = "admin"
    NOVA_HOST = "50.56.41.213"

    enable_debug(sys.stdout)

    os_driver = get_driver(Provider.OPENSTACK_V1_1)(NOVA_USERNAME, NOVA_API_KEY, False, host=NOVA_HOST, port=8774,
                                                   auth_provider=KeyStoneAuthProvider(8081))

    class Struct(object):
        def __init__(self, id):
            self.id = id

    #    print os_driver.create_node(name='az-test', image=Struct(3), size=Struct(2),
    #                                ex_files={'/root/file.txt': 'blah-blah-blah'})

    #    print os_driver.ex_image_details(10)
    #    print os_driver.list_images()

    #    print os_driver.ex_size_details(1)

    nodes = os_driver.list_nodes()
    print os_driver.list_images()
    print os_driver.list_sizes()
#    node = nodes[0]
#    print node.state
#    node.reboot()
#    print node.state
#    print os_driver.ex_soft_reboot_node(os_driver.ex_get_node_details(21))

#    print os_driver.ex_list_floating_ips()

#    print os_driver.ex_limits()
#    print os_driver.ex_save_image(Struct(23), 'custom')
#    print os_driver.ex_delete_image(10)

#    print os_driver.ex_set_password(Struct(23), '123456')

#    os_driver.ex_set_server_name(Struct(23), 'az-test-updated')
#    os_driver.ex_set_ipv6_address(Struct(23), '::babe:67.23.10.132')
#    os_driver.ex_set_ipv4_address(Struct(23), '172.18.102.34')

#    print os_driver.ex_list_floating_ips()

#    print os_driver.ex_get_floating_ip_details(1)

#    print os_driver.ex_allocate_floating_ip()
#    print os_driver.ex_release_floating_ip(1)

#    print os_driver.ex_associate_floating_ip(1, '172.18.102.35')
#    rs_driver = get_driver(Provider.RACKSPACE)('paypal9', 'f22efeb004d2f1d54f47857891f8fab9')
#
#    print rs_driver.list_nodes()
