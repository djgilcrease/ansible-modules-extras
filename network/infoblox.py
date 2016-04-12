#!/usr/bin/python

import re
import functools

try:
    import requests
    HAS_REQUESTS=True
except ImportError:
    HAS_REQUESTS=False


try:
    import json
    HAS_JSON=True
except ImportError:
    try:
        import simplejson as json
        HAS_JSON=True
    except ImportError:
        HAS_JSON=False


DOCUMENTATION = '''
---
module: infoblox
short_description: Manage InfoBlox
description:
     - Manage InfoBlox
version_added: "2.0"
author: "Dj Gilcrease (https://github.com/djgilcrease)"
options:
    host:
        description:
          - Infoblox Host
        required: true
        default: null
    verify_ssl:
        description:
          - Validate SSL certs.  Note, if running on python without SSLContext
            support (typically, python < 2.7.9) you will have to set this to C(no)
            as pysphere does not support validating certificates on older python.
            Prior to 2.1, this module would always validate on python >= 2.7.9 and
            never validate on python <= 2.7.8.
        required: false
        default: no
        choices: ['yes', 'no']
    user:
        description:
          - Username to connect to infoblox as.
        required: true
        default: null
    password:
        description:
          - Password of the user to connect to infoblox as.
        required: true
        default: null
    wapi_version:
        description:
          - The wapi version to use
        required: false
        default: '1.6'
    dns_view:
        description:
          - IBA default view
        required: false
        default: internal
    network_view:
        description:
          - IBA default network view
        required: false
        default: default
    actions:
        description:
          - List of actions and their config perform
        required: true
        default: null
        choices:
            - create_network
            - delete_network
            - create_networkcontainer
            - delete_networkcontainer
            - get_next_available_network
            - create_host_record:
                address:
                    description:
                      - The ip to assign to this host
                    required: true
                    default: null
                fqdn:
                    description:
                      - The fqdn to assign to this host
                    required: true
            - create_txt_record
            - delete_host_record
            - delete_txt_record
            - add_host_alias
            - delete_host_alias
            - create_cname_record
            - delete_cname_record
            - update_cname_record
            - create_dhcp_range
            - delete_dhcp_range
            - get_next_available_ip:
                network:
                    description:
                      - The nextwork to get the next avaliable API on
                    required: true
                    default: null
            - get_host
            - get_host_by_ip
            - get_ip_by_host
            - get_host_by_extattrs
            - get_host_by_regexp
            - get_txt_by_regexp
            - get_host_extattrs
            - get_network
            - get_network_by_ip
            - get_network_by_extattrs
            - get_network_extattrs
            - update_network_extattrs
            - delete_network_extattrs

requirements:
  - "python >= 2.6"
  - requests
'''


EXAMPLES = '''
- name: Get Network
  infoblox:
    host: "{{ infoblox.host }}"
    user: "admin"
    password: "admin"
    wapi_version: '1.6'
    dns_view: default
    network_view: default
    verify_ssl: no
    fact_base: "{{ infoblox }}"
    action:
      get_network:
          network: "{{ network| default(infoblox.network) }}"
  register: infoblox_info
  when: network_vlan is not defined

- name: Store the Network Information for later use
  set_fact:
    infoblox: "{{ infoblox_info.infoblox }}"
    infoblox_network:
      gateway: "{{ infoblox_info.infoblox.get_network[0].extattrs['Default Gateway'].value }}"
      vlan: "{{ infoblox_info.infoblox.get_network[0].extattrs['VLAN'].value }}"
      netmask: "{{ infoblox.netmask.get(infoblox_info.infoblox.get_network[0].netmask|to_ascii) }}"
      netmask_num: "{{ infoblox_info.infoblox.get_network[0].netmask }}"
  when: infoblox_info.infoblox is defined

- name: Check Host Record in InfoBlox
  infoblox:
    host: "{{ infoblox.host }}"
    user: "admin"
    password: "admin"
    wapi_version: '1.6'
    dns_view: default
    network_view: default
    verify_ssl: no
    fact_base: "{{ infoblox }}"
    action:
      get_ip_by_host:
          fqdn: "{{ inventory_hostname }}"
  register: infoblox_info

- name: Merge the infoblox results
  set_fact:
    infoblox: "{{ infoblox_info.infoblox }}"
  when: infoblox_info.infoblox is defined

- set_fact:
    vm_ip: "{{ infoblox_info.infoblox.get_ip_by_host.ips[0] }}"
  when: infoblox_info.infoblox.get_ip_by_host.ips|length > 0

- name: Merge the infoblox results
  set_fact:
    infoblox: "{{ infoblox_info.infoblox }}"
  no_log: true
  when: infoblox_info.infoblox is defined

- name: Create Host Record in InfoBlox
  infoblox:
    host: "{{ infoblox.host }}"
    user: "admin"
    password: "admin"
    wapi_version: '1.6'
    dns_view: default
    network_view: default
    verify_ssl: no
    fact_base: "{{ infoblox }}"
    action:
      create_host_record:
        address: "{{ network| default(infoblox.network)}}"
        fqdn: "{{ inventory_hostname }}"
  register: infoblox_info
  when: infoblox_info.infoblox.get_ip_by_host.ips|length == 0

- name: Save the newip for latter
  set_fact:
      vm_ip: "{{ infoblox_info.infoblox.create_host_record.ipv4addrs[0].ipv4addr }}"
  when: infoblox_info.infoblox.create_host_record is defined
'''


class InfobloxNotFoundException(Exception):
    pass

class InfobloxNoIPavailableException(Exception):
    pass

class InfobloxNoNetworkAvailableException(Exception):
    pass

class InfobloxGeneralException(Exception):
    pass

class InfobloxBadInputParameter(Exception):
    pass

class Infoblox(object):
    """https://ipam.illinois.edu/wapidoc/index.html"""

    def __init__(self, host, user, password, wapi_version, dns_view, network_view, verify_ssl=False):
        """ Class initialization method
        :param host: IBA IP address of management interface
        :param user: IBA user name
        :param password: IBA user password
        :param wapi_version: IBA WAPI version (example: 1.0)
        :param dns_view: IBA default view
        :param network_view: IBA default network view
        :param verify_ssl: IBA SSL certificate validation (example: False)
        """
        self.host = host
        self.user = user
        self.password = password
        self.wapi_version = wapi_version
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify_ssl = verify_ssl
        self.base_url = 'https://{host}/wapi/v{wapi_version}'.format(host=self.host, wapi_version=self.wapi_version)

        # curry the requests calls so we dont have to see auth=(self.user, self.password), verify=self.verify_ssl
        # everywhere we make a request
        self._get = functools.partial(requests.get, auth=(self.user, self.password), verify=self.verify_ssl)
        self._post = functools.partial(requests.post, auth=(self.user, self.password), verify=self.verify_ssl)
        self._put = functools.partial(requests.put, auth=(self.user, self.password), verify=self.verify_ssl)
        self._delete = functools.partial(requests.delete, auth=(self.user, self.password), verify=self.verify_ssl)

    def request(self, url, rqtype="get", **kwargs):
        req_func = getattr(self, '_' + rqtype)
        r = req_func(url=url, **kwargs)
        if r.status_code in [200, 201]:
            return r.json()
        else:
            r_json = r.json()
            if 'text' in r_json:
                if 'code' in r_json and r_json['code'] == 'Client.Ibap.Data':
                    raise InfobloxNoIPavailableException(r_json['text'])
                else:
                    raise InfobloxGeneralException(r_json['text'])
            else:
                r.raise_for_status()

    def get_next_available_ip(self, network, num=1):
        """ Implements IBA next_available_ip REST API call
        Returns IP v4 address
        :param network: network in CIDR format
        """
        rest_url = self.base_url + '/network?network=' + network + '&network_view=' + self.network_view
        network_view = self.request(rest_url)
        for net in network_view:
            net_ref = net['_ref']
            rest_url = self.base_url + '/' + net_ref + '?_function=next_available_ip&num={num}'.format(num=num)
            ip_info = self.request(rest_url, rqtype="post")

            return ip_info, False, "Fetched {} IPs on {}".format(num, network)

        return None, False, "{} IPs are not free on {}".format(num, network)

    def create_host_record(self, address, fqdn, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to create IBA host record
        Returns IP v4 address assigned to the host
        :param address: IP v4 address or NET v4 address in CIDR format to get next_available_ip from
        :param fqdn: hostname in FQDN
        """
        if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$", address):
            ipv4addr = 'func:nextavailableip:' + address
        else:
            if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", address):
                ipv4addr = address
            else:
                raise InfobloxBadInputParameter('Expected IP or NET address in CIDR format')

        rest_url = self.base_url + '/record:host' + '?_return_fields=' + fields
        payload = {
            "ipv4addrs": [{
                    "configure_for_dhcp": False,
                    "ipv4addr": ipv4addr
            }],
            "name": fqdn,
            "view": self.dns_view
        }
        host_info = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return host_info, True, "Created Host: {} for {}".format(address, fqdn)

    def create_txt_record(self, text, fqdn, fields='name,text,view'):
        """ Implements IBA REST API call to create IBA txt record
        Returns IP v4 address assigned to the host
        :param text: free text to be added to the record
        :param fqdn: hostname in FQDN
        """
        rest_url = self.base_url + '/record:txt' + '?_return_fields=' + fields
        payload = {
            "text": text,
            "name": fqdn,
            "view": self.dns_view
        }
        host_info = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return host_info, True, "Created TXT: {} for {}".format(text, fqdn)

    def delete_host_record(self, fqdn, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to delete IBA host record
        :param fqdn: hostname in FQDN
        """
        rest_url = self.base_url + '/record:host?name=' + fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        dns_view = self.request(rest_url)
        for host in dns_view:
            host_ref = host['_ref']
            if host_ref and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn:
                rest_url = self.base_url + '/' + host_ref
                host_info = self.request(rest_url, rqtype="delete")
                return host_info, True, "Deleted Host: {}".format(fqdn)

        return None, False, "Host: {}, does not exist".format(fqdn)

    def delete_txt_record(self, fqdn, fields='name,text,view'):
        """ Implements IBA REST API call to delete IBA TXT record
        :param fqdn: hostname in FQDN
        """
        rest_url = self.base_url + '/record:txt?name=' + fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        dns_view = self.request(rest_url)
        for host in dns_view:
            host_ref = host['_ref']
            if host_ref and re.match("record:txt\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn:
                rest_url = self.base_url + '/' + host_ref
                host_info = self.request(rest_url, rqtype="delete")
                return host_info, True, "Deleted TXT: {}".format(fqdn)

        return None, False, "TXT: {}, does not exist".format(fqdn)

    def add_host_alias(self, host_fqdn, alias_fqdn, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to add an alias to IBA host record
        :param host_fqdn: host record name in FQDN
        :param alias_fqdn: host record name in FQDN
        """
        rest_url = self.base_url + '/record:host?name=' + host_fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        dns_view = self.request(rest_url)
        payload = {"aliases": [alias_fqdn]}
        for host in dns_view:
            host_ref = host['_ref']
            if host_ref and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn:
                aliases = dns_view[0].get('aliases', [])
                if alias_fqdn in aliases:
                    return None, False, "ALIAS: {} for {} already exists".format(alias_fqdn, host_fqdn)

                payload['aliases'] += aliases

                rest_url = self.base_url + '/' + host_ref + '?_return_fields=' + fields
                host_info = self.request(rest_url, rqtype="put", data=json.dumps(payload))
                return host_info, True, "Added ALIAS: {} for {}".format(alias_fqdn, host_fqdn)

        return None, False, "Host: {}, does not exist".format(host_fqdn)

    def delete_host_alias(self, host_fqdn, alias_fqdn, fields='name,aliases'):
        """ Implements IBA REST API call to add an alias to IBA host record
        :param host_fqdn: host record name in FQDN
        :param alias_fqdn: host record name in FQDN

        https://ipam.illinois.edu/wapidoc/objects/record.host.html
        """
        rest_url = self.base_url + '/record:host?name=' + host_fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        dns_view = self.request(rest_url)
        host_ref = dns_view[0]['_ref']
        if (host_ref
            and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn
            and 'aliases' in dns_view[0]):
            aliases = dns_view[0]['aliases']
            if fqdn not in aliases:
                return None, False, "ALIAS: {} for {}, does not exist".format(alias_fqdn, host_fqdn)

            aliases.remove(alias_fqdn)
            payload = {"aliases": aliases}
            rest_url = self.base_url + '/' + host_ref + '&_return_fields=' + fields
            host_info = self.request(rest_url, rqtype="put", data=json.dumps(payload))
            return host_info, True, "Deleted ALIAS: {} for {}".format(alias_fqdn, host_fqdn)

        return None, False, "Host: {} for {}, does not exist".format(alias_fqdn, host_fqdn)

    def create_cname_record(self, canonical, name, fields='canonical,name,view'):
        """ Implements IBA REST API call to create IBA cname record
        :param canonical: canonical name in FQDN format
        :param name: the name for a CNAME record in FQDN format

        https://ipam.illinois.edu/wapidoc/objects/record.cname.html
        """
        rest_url = self.base_url + '/record:cname' + '?_return_fields=' + fields
        payload = {
            "canonical": canonical,
            "name": name,
            "view": self.dns_view
        }
        host_info = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return host_info, True, "Created CNAME: {} -> {}".format(name, canonical)

    def delete_cname_record(self, fqdn, fields='canonical,name,view'):
        """ Implements IBA REST API call to delete IBA cname record
        :param fqdn: cname in FQDN

        https://ipam.illinois.edu/wapidoc/objects/record.cname.html
        """
        rest_url = self.base_url + '/record:cname?name=' + fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        dns_view = self.request(rest_url)
        cname_ref = dns_view[0]['_ref']
        if cname_ref and re.match("record:cname\/[^:]+:([^\/]+)\/", cname_ref).group(1) == fqdn:
            rest_url = self.base_url + '/' + cname_ref
            host_info = self.request(rest_url, rqtype="delete")
            return host_info, True, "Deleted CNAME: {}".format(fqdn)

        return None, False, "CNAME: {}, does not exist".format(fqdn)

    def update_cname_record(self, canonical, name, fields='canonical,name,view'):
        """ Implements IBA REST API call to update or repoint IBA cname record
        :param canonical: canonical name in FQDN format
        :param name: the name for the new CNAME record in FQDN format

        https://ipam.illinois.edu/wapidoc/objects/record.cname.html
        """
        rest_url = self.base_url + '/record:cname' + '?_return_fields=' + fields
        host_info = self.request(rest_url, data=json.dumps({'name': name}))
        cname_ref = host_info[0]['_ref']
        payload = {
            "canonical": canonical
        }
        rest_url = self.base_url + '/' + cname_ref + '?_return_fields=' + fields
        host_info = self.request(rest_url, rqtype="put", data=json.dumps(payload))

        return host_info, True, "Updated CNAME: {} -> {}".format(name, canonical)

    def create_dhcp_range(self, start_ip_v4, end_ip_v4, fields='comment,end_addr,network,network_view,start_addr,bootserver,bootfile'):
        """ Implements IBA REST API call to add DHCP range for given start and end addresses
        :param start_ip_v4: IP v4 address
        :param end_ip_v4: IP v4 address

        https://ipam.illinois.edu/wapidoc/objects/range.html
        """
        rest_url = self.base_url + '/range' + '?_return_fields=' + fields
        payload = {
            "start_addr": start_ip_v4,
            "end_addr": end_ip_v4
        }
        dhcp_range = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return dhcp_range, True, "Created DHCP Range: {} - {}".format(start_ip_v4, end_ip_v4)

    def delete_dhcp_range(self, start_ip_v4, end_ip_v4, fields='comment,end_addr,network,network_view,start_addr,bootserver,bootfile'):
        """ Implements IBA REST API call to delete DHCP range for given start and end addresses
        :param start_ip_v4: IP v4 address
        :param end_ip_v4: IP v4 address

        https://ipam.illinois.edu/wapidoc/objects/range.html
        """
        rest_url = self.base_url + '/range?start_addr=' + start_ip_v4 + '?end_addr=' + end_ip_v4 + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_view = self.request(rest_url)
        if not network_view:
            return None, False, "DHCP Range: {} - {}, does not exist".format(start_ip_v4, end_ip_v4)

        range_ref = r_json[0]['_ref']
        rest_url = self.base_url + '/' + range_ref + '&_return_fields=' + fields
        dhcp_range = self.request(rest_url, rqtype="delete")

        return dhcp_range, True, "Deleted DHCP Range: {} - {}".format(start_ip_v4, end_ip_v4)

    def get_host(self, fqdn, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to retrieve host record fields
        Returns hash table of fields with field name as a hash key
        :param fqdn: hostname in FQDN
        :param fields: comma-separated list of field names (optional)
        """
        rest_url = self.base_url + '/record:host?name=' + fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        host_info = self.request(rest_url)

        return host_info, False, "Fetched Host: {}".format(fqdn)

    def get_host_by_regexp(self, fqdn, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to retrieve host records by fqdn regexp filter
        Returns array of host names in FQDN matched to given regexp filter
        :param fqdn: hostname in FQDN or FQDN regexp filter
        """
        rest_url = self.base_url + '/record:host?name~=' + fqdn + '&view=' + self.dns_view +  '&_return_fields=' + fields
        host_info = self.request(rest_url)

        return host_info, False, "Fetched Host: {}".format(fqdn)

    def get_txt_by_regexp(self, fqdn, fields='name,text,view'):
        """ Implements IBA REST API call to retrieve TXT records by fqdn regexp filter
        Returns dictonary of host names in FQDN matched to given regexp filter with the TXT value
        :param fqdn: hostname in FQDN or FQDN regexp filter
        """
        rest_url = self.base_url + '/record:txt?name~=' + fqdn + '&view=' + self.dns_view + '&_return_fields=' + fields
        host_info = self.request(rest_url)

        return host_info, False, "Fetched TXT: {}".format(fqdn)

    def get_host_by_ip(self, ip_v4, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to find hostname by IP address
        Returns array of host names in FQDN associated with given IP address
        :param ip_v4: IP v4 address
        """
        rest_url = self.base_url + '/record:host?ipv4addr=' + ip_v4 + '&view=' + self.dns_view + '&_return_fields=' + fields
        host_info = self.request(rest_url)

        return host_info, False, "Fetched Hosts by ip {}".format(ip_v4)

    def get_ip_by_host(self, fqdn):
        """ Implements IBA REST API call to find IP addresses by hostname
        Returns array of IP v4 addresses associated with given hostname
        :param fqdn: hostname in FQDN
        """
        rest_url = self.base_url + '/record:host?name=' + fqdn + '&view=' + self.dns_view + '&_return_fields=ipv4addrs'
        host_info = self.request(rest_url)
        ret = {'ips': []}
        for host in host_info:
            for addr in host['ipv4addrs']:
                ret['ips'].append(addr['ipv4addr'])

        return ret, False, "Fetched IPs for {}".format(fqdn)

    def get_network(self, network, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to retrieve network object fields
        Returns hash table of fields with field name as a hash key
        :param network: network in CIDR format
        :param fields: comma-separated list of field names
                (optional, returns network in CIDR format and netmask if not specified)
        """
        rest_url = self.base_url + '/network?network=' + network + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)

        return network_info, False, "Fetched Network {}".format(network)

    def get_network_by_ip(self, ip_v4, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to find network by IP address which belongs to this network
        Returns network in CIDR format
        :param ip_v4: IP v4 address
        """
        rest_url = self.base_url + '/network?contains_address=' + ip_v4 + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)

        return network_info, False, "Fetched Network for {}".format(ip_v4)

    def get_network_by_extattrs(self, attributes, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to find a network by it's extensible attributes
        Returns array of networks in CIDR format
        :param attributes: comma-separated list of attrubutes name/value pairs in the format:
            attr_name=attr_value - exact match for attribute value
            attr_name:=attr_value - case insensitive match for attribute value
            attr_name~=regular_expression - match attribute value by regular expression
            attr_name>=attr_value - search by number greater than value
            attr_name<=attr_value - search by number less than value
            attr_name!=attr_value - search by number not equal of value
        """
        rest_url = self.base_url + '/network?*' + "&*".join(attributes.split(",")) + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)

        return network_info, False, "Fetched Network by attribute {}".format(attributes)

    def get_host_by_extattrs(self, attributes, fields='name,ipv4addrs,zone,aliases'):
        """ Implements IBA REST API call to find host by it's extensible attributes
        Returns array of hosts in FQDN
        :param attributes: comma-separated list of attrubutes name/value pairs in the format:
            attr_name=attr_value - exact match for attribute value
            attr_name:=attr_value - case insensitive match for attribute value
            attr_name~=regular_expression - match attribute value by regular expression
            attr_name>=attr_value - search by number greater than value
            attr_name<=attr_value - search by number less than value
            attr_name!=attr_value - search by number not equal of value
        """
        rest_url = self.base_url + '/record:host?*' + "&*".join(attributes.split(",")) + '&view=' + self.dns_view + '&_return_fields=' + fields
        host_info = self.request(rest_url)

        return host_info, False, "Fetched Hosts by attribute {}".format(attributes)

    def update_network_extattrs(self, network, attributes, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to add or update network extensible attributes
        :param network: network in CIDR format
        :param attributes: hash table of extensible attributes with attribute name as a hash key
        """
        rest_url = self.base_url + '/network?network=' + network + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)
        extattrs = {}
        for attr_name, attr_value in attributes.iteritems():
            extattrs[attr_name]['value'] = attr_value

        networks = []
        for network in network_info:
            network_ref = network['_ref']
            payload = {
                "extattrs": extattrs
            }
            rest_url = self.base_url + '/' + network_ref
            self.request(rest_url, rqtype="put", data=json.dumps(payload))
            network['extattrs'] = extattrs
            networks.append(network)

        return networks, False, "Updated Network attributes {}".format(attributes)

    def delete_network_extattrs(self, network, attributes, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to delete network extensible attributes
        :param network: network in CIDR format
        :param attributes: array of extensible attribute names
        """
        rest_url = self.base_url + '/network?network=' + network + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)

        networks = []
        for network in network_info:
            network_ref = network['_ref']
            extattrs = network['extrattrs']
            for attr_name in attributes:
                extattrs.pop(attr_name, None)

            network['extrattrs'] = extattrs

            payload = {
                "extattrs": extattrs
            }
            rest_url = self.base_url + '/' + network_ref
            self.request(rest_url, rqtype="put", data=json.dumps(payload))
            networks.append(network)

        return networks, False, "Deleted Network attributes {}".format(attributes)

    def create_network(self, network, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to create DHCP network object
        :param network: network in CIDR format
        """
        rest_url = self.base_url + '/network' + '?_return_fields=' + fields
        payload = {
            "network": network,
            "network_view": self.network_view
        }
        network_info = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return networks, False, "Created Network {}".format(network)

    def delete_network(self, network, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to delete DHCP network object
        :param network: network in CIDR format
        """
        rest_url = self.base_url + '/network?network=' + network + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)
        for network in network_info:
            rest_url = self.base_url + '/' + network['_ref']
            self.request(url=rest_url, rqtype="delete")

        return network_info, False, "Deleted Network {}".format(network)

    def create_networkcontainer(self, networkcontainer, fields='comment,network,network_view'):
        """ Implements IBA REST API call to create DHCP network containert object
        :param networkcontainer: network container in CIDR format
        """
        rest_url = self.base_url + '/networkcontainer' + '?_return_fields=' + fields
        payload = {
            "network": networkcontainer,
            "network_view": self.network_view
        }
        network_info = self.request(rest_url, rqtype="post", data=json.dumps(payload))

        return networks, False, "Created Network Conatiner {}".format(networkcontainer)

    def delete_networkcontainer(self, networkcontainer, fields='comment,network,network_view'):
        """ Implements IBA REST API call to delete DHCP network container object
        :param networkcontainer: network container in CIDR format
        """
        rest_url = self.base_url + '/networkcontainer?network=' + networkcontainer + '&network_view=' + self.network_view + '&_return_fields=' + fields
        network_info = self.request(rest_url)
        for network in network_info:
            rest_url = self.base_url + '/' + network['_ref']
            self.request(url=rest_url, rqtype="delete")

        return network_info, False, "Deleted Network Container {}".format(networkcontainer)

    def get_next_available_network(self, networkcontainer, cidr, num=1, fields='network,netmask,extattrs'):
        """ Implements IBA REST API call to retrieve next available network of network container
        Returns network address in CIDR format
        :param networkcontainer: network container address in CIDR format
        :param cidr: requested network length (from 0 to 32)
        """
        rest_url = self.base_url + '/networkcontainer?network=' + networkcontainer + '&network_view=' + self.network_view
        network_info = self.request(rest_url)
        networks = []
        for network in network_info:
            rest_url = self.base_url + '/' + network['_ref'] + '?_function=next_available_network&cidr={cidr}&num={num}&_return_fields={fields}'.format(cidr=cidr,
                                                                                                                                                        num=num,
                                                                                                                                                        fields=fields)
            ni = self.request(url=rest_url, rqtype="post")
            networks.append(ni)

        return networks, False, "Fetched next networks in {}".format(networkcontainer)


def main():
    global module
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            user=dict(required=True, type='str'),
            password=dict(required=True, type='str', no_log=True),
            wapi_version=dict(required=False, type='str', default='1.6'),
            dns_view=dict(required=False, type='str', default='internal'),
            network_view=dict(required=False, type='str', default='default'),
            verify_ssl=dict(required=False, type='bool', default=False),
            fact_base=dict(required=False, type='dict', default={}),
            action=dict(required=True, type='dict'),
        ),
        supports_check_mode=False,
        mutually_exclusive=[],
        required_together=[])

    if not HAS_REQUESTS:
        module.fail_json(msg='Missing requests dependancy')

    if not HAS_JSON:
        module.fail_json(msg='Missing json or simplejson dependancy')

    infoblox = module.params.pop('fact_base', {})
    action = module.params.pop('action')
    client = Infoblox(**module.params)

    import traceback
    for name, kwargs in action.iteritems():
        if not hasattr(client, name):
            module.fail_json(msg='{0} is not a valid action'.format(name))

        func = getattr(client, name)

        try:
            infoblox[name], changed, msg = func(**kwargs)
        except Exception as e:
            module.fail_json(msg=traceback.format_exc())

    module.exit_json(msg=msg,
                     infoblox=infoblox,
                     changed=changed)


# this is magic, see lib/ansible/module_common.py
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
