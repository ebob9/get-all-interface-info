#!/usr/bin/env python
"""
CGNX Get all interface info for all sites.
Python v2.7+.x only, not python3 compatible yet.

cloudgenix@ebob9.com

"""
# standard modules
import argparse
import json
import logging
import datetime
import os
import sys

# CloudGenix SDK
import cloudgenix

# bar
from progressbar import Bar, ETA, Percentage, ProgressBar

# Global Vars
TIME_BETWEEN_API_UPDATES = 60  # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7  # hours
SCRIPT_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix Site Interface info -> CSV Generator'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


def siteid_to_name_dict(session):
    """
    Create a Site ID to name xlation table.
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with siteid key to site name.
    """
    xlate_dict = {}
    id_info_dict = {}
    id_list = []

    result = session.get.sites()
    status = result.cgx_status
    raw_sites = result.cgx_content

    sites_list = raw_sites.get('items', None)

    # print(json.dumps(sites_list, indent=4))

    if not status or not sites_list:
        logger.info("ERROR: unable to get sites for account '%s'.", session.tenant_name)
        return xlate_dict, id_list, id_info_dict

    # build translation dict
    for site in sites_list:
        # print(json.dumps(site, indent=4))
        name = site.get('name')
        id = site.get('id')

        if name and id:
            xlate_dict[id] = name

        if id:
            id_list.append(id)
            id_info_dict[id] = site

    return xlate_dict, id_list, id_info_dict


def elements_to_name_dict(session):
    """
    Create a Site ID to name xlation table.
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with siteid key to site name.
    """
    name_xlate_dict = {}
    site_xlate_dict = {}
    id_list = []

    result = session.get.elements()
    status = result.cgx_status
    raw_elements = result.cgx_content

    elements_list = raw_elements.get('items', None)

    # print(json.dumps(elements_list, indent=4))

    if not status or not elements_list:
        logger.info("ERROR: unable to get elements for account '%s'.", session.tenant_name)
        return name_xlate_dict, site_xlate_dict, id_list

    # build translation dict
    for element in elements_list:
        name = element.get('name')
        id = element.get('id')
        site = element.get('site_id', None)

        if name and id:
            name_xlate_dict[id] = name

        if site and id:
            site_xlate_dict[id] = site

        if id:
            id_list.append(id)

    return name_xlate_dict, site_xlate_dict, id_list


def securityzone_to_name_dict(session):
    """
    Create a Site ID to name xlation table.
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with siteid key to site name.
    """
    name_xlate_dict = {}
    id_list = []

    result = session.get.securityzones()
    status = result.cgx_status
    raw_securityzones = result.cgx_content

    securityzones_list = raw_securityzones.get('items', None)

    # print(json.dumps(securityzones_list, indent=4))

    if not status or not securityzones_list:
        logger.info("ERROR: unable to get securityzones for account '%s'.", session.tenant_name)
        return name_xlate_dict, id_list

    # build translation dict
    for securityzone in securityzones_list:
        name = securityzone.get('name')
        id = securityzone.get('id')

        if name and id:
            name_xlate_dict[id] = name

        if id:
            id_list.append(id)

    return name_xlate_dict, id_list


def interface_query(site_id, element_id, session):
    interface_return = []
    if_id_to_name_return = {}
    if_id_data = {}

    result = session.get.interfaces(site_id, element_id)
    status = result.cgx_status
    raw_interfaces = result.cgx_content

    interfaces_list = raw_interfaces.get('items', None)

    # print(json.dumps(interfaces_list, indent=4))

    if not status or not interfaces_list:
        logger.info("ERROR: unable to get interfaces for element '%s' at site '%s'.",
                    element_id, site_id)
        return interface_return, if_id_to_name_return, if_id_data

    # build translation dict

    for interface in interfaces_list:
        name = interface.get('name', "")
        id = interface.get('id', None)

        if id:
            if_id_to_name_return[id] = name
            interface_return.append(interface)
            if_id_data[id] = interface

    return interface_return, if_id_to_name_return, if_id_data


def wan_network_dicts(session):
    """
    Create a Site ID <-> Name xlation constructs
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with wannetworkid key to wan_network name. wan_network_list, a list of wan_network IDs
    """
    id_xlate_dict = {}
    name_xlate_dict = {}
    wan_network_id_list = []
    wan_network_id_type = {}

    result = session.get.wannetworks()
    status = result.cgx_status
    raw_wan_networks = result.cgx_content

    wan_networks_list = raw_wan_networks.get('items', None)

    if not status or not wan_networks_list:
        logger.info("ERROR: unable to get wan networks for account '%s'.", session.tenant_name)
        return id_xlate_dict, name_xlate_dict, wan_network_id_list, wan_network_id_type

    # build translation dict
    for wan_network in wan_networks_list:
        name = wan_network.get('name')
        wan_network_id = wan_network.get('id')
        wn_type = wan_network.get('type')

        if name and wan_network_id:
            id_xlate_dict[wan_network_id] = "{0} ({1})".format(name, wn_type)
            name_xlate_dict[name] = wan_network_id
            wan_network_id_list.append(wan_network_id)

        if wan_network_id and wn_type:
            wan_network_id_type[wan_network_id] = wn_type

    return id_xlate_dict, name_xlate_dict, wan_network_id_list, wan_network_id_type


def circuit_categories_dicts(session):
    """
    Create a circuit Catagory ID to name table
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with wannetworkid key to wan_network name. wan_network_list, a list of wan_network IDs
    """
    id_xlate_dict = {}

    result = session.get.waninterfacelabels()
    status = result.cgx_status
    raw_wan_labels = result.cgx_content

    wan_labels_list = raw_wan_labels.get('items', None)

    if not status or not wan_labels_list:
        logger.info("ERROR: unable to get circuit catagories for account '%s'.", session.tenant_name)
        return id_xlate_dict

    # build translation dict
    for wan_label in wan_labels_list:
        name = wan_label.get('name')
        wan_label_id = wan_label.get('id')

        if name and wan_label_id:
            id_xlate_dict[wan_label_id] = name

    return id_xlate_dict


def network_context_dicts(session):
    """
    Create a network context id to Name table
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with wannetworkid key to wan_network name. wan_network_list, a list of wan_network IDs
    """
    id_xlate_dict = {}

    result = session.get.networkcontexts()
    status = result.cgx_status
    raw_network_contexts = result.cgx_content

    network_contexts_list = raw_network_contexts.get('items', None)

    if not status or not network_contexts_list:
        logger.info("ERROR: unable to get network contexts for account '%s'.", session.tenant_name)
        return id_xlate_dict

    # build translation dict
    for network_context in network_contexts_list:
        name = network_context.get('name')
        network_context_id = network_context.get('id')

        if name and network_context_id:
            id_xlate_dict[network_context_id] = name

    return id_xlate_dict


def appdefs_to_name_dict(session):
    """
    Create a Site ID to name xlation table.
    :param session: cloudgenix.API() session object
    :return: xlate_dict, a dict with siteid key to site name.
    """
    xlate_dict = {}
    id_list = []

    result = session.get.appdefs()
    status = result.cgx_status
    raw_appdefs = result.cgx_content

    appdefs_list = raw_appdefs.get('items', None)

    if not status or not appdefs_list:
        logger.info("ERROR: unable to get appdefs for account '%s'.", session.tenant_name)
        return xlate_dict, id_list

    # build translation dict
    for appdef in appdefs_list:
        name = appdef.get('display_name')
        id = appdef.get('id')

        if name and id:
            xlate_dict[id] = name

        if id:
            id_list.append(id)

    return xlate_dict, id_list


def policyset_to_name_dict(session):
    xlate_dict = {}
    id_list = []

    result = session.get.policysets()
    status = result.cgx_status
    raw_policyset = result.cgx_content

    policyset_list = raw_policyset.get('items', None)

    if not status or not policyset_list:
        logger.info("ERROR: unable to get policysets for account '%s'.", session.tenant_name)
        return xlate_dict, id_list

    # build translation dict
    for policyset in policyset_list:
        name = policyset.get('name')
        id = policyset.get('id')

        if name and id:
            xlate_dict[id] = name

        if id:
            id_list.append(id)

    return xlate_dict, id_list


def securitypolicyset_to_name_dict(session):
    xlate_dict = {}
    id_list = []

    result = session.get.securitypolicysets()
    status = result.cgx_status
    raw_securitypolicyset = result.cgx_content

    securitypolicyset_list = raw_securitypolicyset.get('items', None)

    if not status or not securitypolicyset_list:
        logger.info("ERROR: unable to get securitypolicysets for account '%s'.", session.tenant_name)
        return xlate_dict, id_list

    # build translation dict
    for securitypolicyset in securitypolicyset_list:
        name = securitypolicyset.get('name')
        securitypolicyset_id = securitypolicyset.get('id')

        if name and securitypolicyset_id:
            xlate_dict[securitypolicyset_id] = name

        if securitypolicyset_id:
            id_list.append(securitypolicyset_id)

    return xlate_dict, id_list


def write_to_csv(csv_file_name, site_name="", site_type="", site_admin_state="", element_name="", interface_name="",
                 intf_used_for="", site_policyset_name="", site_security_policyset_name="", interface_admin_state="",
                 mac_address="", vlan="", interface_str="", if_config_type="", interface_mtu="",
                 network_context="", local_global="", security_zone="", swi_name="", conf_bw_up="", conf_bw_down="",
                 pcm_enabled="", lqm_enabled="", qos_enabled="", circuit_category="", wan_network_name="", nat_addr="",
                 nat_port=0, operational_state="", operational_speed="", operational_duplex="", operational_link="",
                 operational_device=""):
    # global variable write.
    write_str = '{0},{1},{2},{3},="{4}",{5},{6},{7},{8},{9},' \
                '{10},{11},{12},="{13}",{14},{15},{16},{17},' \
                '{18},{19},{20},{21},{22},{23},{24},{25},' \
                '{26},{27},{28},{29},{30},{31}\n' \
        .format(
        # Site Name
        site_name,
        # Site Type
        site_type,
        # Site Mode
        site_admin_state,
        # ION name
        element_name,
        # Interface name
        interface_name,
        # Interface used for
        intf_used_for,
        # Network Policy
        site_policyset_name,
        # Port Admin State
        interface_admin_state,
        # Operational State
        operational_state,
        # Speed
        operational_speed,
        # Duplex
        operational_duplex,
        # Link State
        operational_link,
        # MAC Address
        mac_address,
        # VLAN
        vlan,
        # Address/Mask List
        interface_str,
        # Config by
        if_config_type,
        # MTU
        interface_mtu,
        # Network Context
        network_context,
        # Local or Global
        local_global,
        # Circuit Name
        swi_name,
        # Configured BW Up
        conf_bw_up,
        # Configured BW Down
        conf_bw_down,
        # PCM
        pcm_enabled,
        # LQM
        lqm_enabled,
        # QoS
        qos_enabled,
        # Circuit Catagory
        circuit_category,
        # WAN Network Name
        wan_network_name,
        # Security Policy
        site_security_policyset_name,
        # Security Zone
        security_zone,
        # Configured NAT address
        "" if not nat_addr else nat_addr,
        # Configured NAT Port
        "" if nat_port == 0 else nat_port,
        # UNIX Device Name
        operational_device
    )

    with open(csv_file_name, 'a') as csv_file:
        csv_file.write(write_str)
        csv_file.flush()

    return


def go():
    # system struct
    system_list = []

    # if_id_to_name lookup dictionary
    if_id_to_name = {}

    # role transation
    role_xlate = {
        'HUB': 'DC',
        'SPOKE': 'Branch'
    }

    ############################################################################
    # Begin Script, start login / argument handling.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://controller.cloudgenix.com:8443",
                                  default=None)

    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    options_group = parser.add_argument_group('Options', 'These options enable different output information')
    group2 = options_group.add_mutually_exclusive_group()
    group2.add_argument("--ipv4", "-4", help="IPv4 addresses only (default)",
                        action='store_true', default=True)
    group2.add_argument("--ipv6", "-6", help="IPv6 addresses only",
                        action='store_true', default=False)
    group2.add_argument("--all", "-A", help="All Address Families",
                        action='store_true', default=False)

    args = vars(parser.parse_args())

    # set address family request.
    if args['all']:
        address_family = 'A'
    elif args['ipv6']:
        address_family = '6'
    else:
        # default
        address_family = '4'

    ############################################################################
    # Instantiate API
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ############################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################

    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # interactive or cmd-line specified initial login

    while cgx_session.tenant_name is None:
        cgx_session.interactive.login(args["email"], args["pass"])

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filenames
    interfaces_csv = os.path.join('./', '%s_interfaces_%s.csv' %
                                  (tenant_str, curtime_str))

    print("Creating %s for data output..." % (str(interfaces_csv)))
    with open(interfaces_csv, 'w') as csv_file:
        csv_file.write('Site,Site Type,Site Mode,ION,Interface,Used For,Network Policy,Admin State,'
                       'Operational State,Speed,Duplex,Link State,'
                       'MAC Address,VLAN Tag,Address/Mask List,Configured By,'
                       'Configured MTU,Network Context,Local or Global,Circuit Name,Configured BW Up,'
                       'Configured BW Down,PCM,LQM,QoS,Circuit Category,WAN Network Name,'
                       'Security Policy,Security Zone,Configured NAT Address,'
                       'Configured NAT Port,UNIX Device Name\n')
        csv_file.flush()

    # Create xlation dicts and lists.
    print("Caching Sites..")
    id_site_dict, site_id_list, site_info_dict = siteid_to_name_dict(cgx_session)
    print("Caching Elements..")
    id_element_dict, element_site_dict, element_id_list = elements_to_name_dict(cgx_session)
    print("Caching WAN Networks..")
    id_wannetwork_dict, name_wannetwork_id_dict, wannetwork_id_list, wannetwork_type_dict = wan_network_dicts(
        cgx_session)
    print("Caching Circuit Catagories..")
    id_circuit_categories = circuit_categories_dicts(cgx_session)
    print("Caching Network Contexts..")
    id_network_contexts = network_context_dicts(cgx_session)
    print("Caching Policysets..")
    id_policyset_dict, policyset_id_list = policyset_to_name_dict(cgx_session)
    print("Caching Security Policysets..")
    id_securitypolicyset_dict, securitypolicyset_id_list = securitypolicyset_to_name_dict(cgx_session)
    print("Caching Security Zones..")
    id_securityzone_dict, securityzone_id_list = securityzone_to_name_dict(cgx_session)

    # print(json.dumps(id_wannetwork_dict, indent=4))
    # print(json.dumps(id_securitypolicyset_dict, indent=4))
    #
    # exit()

    id_interface_dict = {}

    firstbar = len(site_id_list) * len(element_id_list) + 1
    barcount = 1

    print("Filling Network Site->Element->Interface table..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    for site in site_id_list:
        elements = []
        # enumerate elements
        for element in element_id_list:
            # Is this element bound to a site?
            site_in = element_site_dict.get(element, None)
            # if it is bound, and bound to this site, add to list.
            if site_in and site_in == site:
                # Query interfaces
                interfaces_list, if_id_to_name_item, if_id_data_entry = interface_query(site, element, cgx_session)
                # add the element to the list
                elements.append({
                    'id': element,
                    'name': id_element_dict.get(element, ""),
                    'interfaces': interfaces_list
                })
                # add the if id name mapping to the main dict
                if_id_to_name.update(if_id_to_name_item)
                # update grand interface list
                id_interface_dict.update(if_id_data_entry)

                # iterate bar and counter.
            barcount += 1
            pbar.update(barcount)

        system_list.append({
            'id': site,
            'name': id_site_dict.get(site, ""),
            'elements': elements
        })
    # finish after iteration.
    pbar.finish()

    # print(json.dumps(if_id_to_name, indent=4))

    secondbar = len(id_interface_dict.keys()) + 1
    barcount = 1

    # Get all of the entries.
    print("Querying all interfaces for current status..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=secondbar).start()

    for site_dict in system_list:
        site_name = site_dict.get('name', "")
        site_id = site_dict.get('id', None)
        # if site, iterate
        if site_id:
            swi_id_dict = {}
            ln_id_dict = {}
            network_to_security_zone_dict = {}
            site_all_prefixes = []
            # save a list of used prefixes as we iterate interfaces for later.
            site_used_prefixes = []

            # query Site WAN Interface info
            cgx_result = cgx_session.get.waninterfaces(site_id)
            swi_status = cgx_result.cgx_status
            swi_query = cgx_result.cgx_content
            if swi_status:
                for swi in swi_query.get('items'):
                    swi_id = swi.get('id')
                    if swi_id:
                        swi_id_dict[swi_id] = swi

            # query LAN Network info
            cgx_result = cgx_session.get.lannetworks(site_id)
            ln_status = cgx_result.cgx_status
            ln_query = cgx_result.cgx_content
            if ln_status:
                for ln in ln_query.get('items'):
                    ln_id = ln.get('id')

                    if ln_id:
                        ln_id_dict[ln_id] = ln

                    # add prefix to site_all_prefixes if it exists.
                    if address_family in ['A', '4']:
                        # iterate into ipv4 config
                        all_ln_ipv4_config = ln.get('ipv4_config', {})
                        all_ln_ipv4_prefixes = all_ln_ipv4_config.get('prefixes', [])
                        if all_ln_ipv4_prefixes:
                            # add prefixes to site all prefix list
                            site_all_prefixes += all_ln_ipv4_prefixes

            # cache network -> Security Zone binding
            cgx_result = cgx_session.get.sitesecurityzones(site_id)
            securityzone_status = cgx_result.cgx_status
            securityzone_query = cgx_result.cgx_content
            if securityzone_status:
                logger.debug("ZONE MAPPING QUERY: %s", json.dumps(securityzone_query, indent=4))
                for securityzonebinding in securityzone_query.get('items'):
                    securityzone_id = securityzonebinding.get('zone_id')
                    bound_networks = securityzonebinding.get('networks', [])
                    for bound_network in bound_networks:
                        network_id = bound_network.get('network_id')
                        if securityzone_id and network_id:
                            network_to_security_zone_dict[network_id] = securityzone_id

            # grab site level details.
            site_details = site_info_dict.get(site_id, {})
            site_policyset_id = site_details.get('policy_set_id')
            site_security_policyset_id = site_details.get('security_policyset_id')
            site_admin_state = site_details.get('admin_state')

            # get site named items:
            site_policyset_name = id_policyset_dict.get(site_policyset_id, "")
            site_security_policyset_name = id_securitypolicyset_dict.get(site_security_policyset_id, "")
            site_type = role_xlate.get(site_details.get('element_cluster_role', 'Other'))

            # print(json.dumps(swi_id_dict, indent=4))
            # print(json.dumps(ln_id_dict, indent=4))
            # print(json.dumps(network_to_security_zone_dict, indent=4))

            # iterate elements
            for element_dict in site_dict.get('elements', []):
                element_name = element_dict.get('name', "")
                element_id = element_dict.get('id', None)
                # if element, iterate.
                if element_id:
                    # iterate interfaces
                    for interface_dict in element_dict.get('interfaces', []):
                        ip_list = []
                        interface_str = ""
                        operational_state = ""
                        operational_status = ""
                        operational_speed = ""
                        operational_duplex = ""
                        operational_link = ""
                        operational_device = ""
                        mac_address = ""
                        lqm_enabled = ""
                        pcm_enabled = ""
                        qos_enabled = ""
                        conf_bw_down = ""
                        conf_bw_up = ""
                        circuit_category = ""
                        swi_name = ""
                        wan_network_name = ""
                        security_zone = ""
                        used_for = ""
                        vlan_id = "NATIVE"
                        interface_name = interface_dict.get('name', "")
                        interface_id = interface_dict.get('id', None)

                        # interface_dict just stores name/id - pull rest out of intf lookup dict.
                        interface_data = id_interface_dict.get(interface_id, {})

                        logger.debug("IDATA: %s", json.dumps(interface_data, indent=4))

                        intf_ipv4_config = interface_data.get('ipv4_config', {})

                        # check if none, translate to empty dict.
                        if not intf_ipv4_config:
                            intf_ipv4_config = {}

                        intf_ipv4_config_type = intf_ipv4_config.get('type', "")

                        intf_used_for = interface_data.get('used_for')
                        # print("USED_FOR: ", repr(intf_used_for))
                        interface_type = interface_data.get('type')
                        intf_conf_nat_port = interface_data.get('nat_port')
                        intf_conf_nat_addr = interface_data.get('nat_address')
                        intf_attached_lan_networks = interface_data.get('attached_lan_networks')
                        interface_admin_state = "Enabled" if interface_data.get('admin_up') else "Disabled"
                        intf_site_wan_interface_id = interface_data.get('site_wan_interface_id')
                        intf_site_wan_interface_ids = interface_data.get('site_wan_interface_ids', [])
                        interface_mtu = interface_data.get('mtu')

                        # if bypasspair, continue to next item in for loop - config info is present on individual ports.

                        # print("INTERFACE TYPE: ", repr(interface_type))
                        if interface_type in ["bypasspair"]:
                            logger.debug("GOT BYPASSPAIR, CONTINUING..")
                            # iterate bar and counter.
                            barcount += 1
                            pbar.update(barcount)

                            continue

                        # calculate real "used for" if not present
                        if not intf_used_for or intf_used_for in ['none']:
                            if "controller" in interface_name:
                                used_for = "Controller"
                            else:
                                used_for = ""

                        else:
                            if intf_used_for in ['private']:
                                used_for = "Private"
                            elif intf_used_for in ['private_wan']:
                                used_for = "Private WAN"
                            elif intf_used_for in ['private_lan']:
                                used_for = "Private LAN"
                            elif intf_used_for in ['public']:
                                used_for = "Internet"
                            else:
                                used_for = intf_used_for.title()

                        # get interface status
                        cgx_result = cgx_session.get.status_interfaces(site_id, element_id, interface_id)
                        query_status = cgx_result.cgx_status
                        interface_status = cgx_result.cgx_content

                        if query_status:
                            # print(interface_status)
                            operational_state = interface_status.get('operational_state')
                            operational_device = interface_status.get('device')
                            port_info = interface_status.get('port', {})
                            # check for null port values on subif/PPPoE
                            if port_info is None:
                                # set to a dict and continue.
                                port_info = {}

                            port_connected = port_info.get('connected', {})

                            logger.debug("PORT INFO: %s", json.dumps(port_info))
                            if port_connected:
                                operational_speed = port_info.get('speed')
                                duplex = port_info.get('full_duplex')
                                if duplex is not None:
                                    if duplex:
                                        operational_duplex = "Full"
                                    else:
                                        operational_duplex = "Half"
                            else:
                                operational_speed = ""
                                operational_duplex = ""

                            operational_link = "Up" if port_connected else "Down"

                            ipv4_addr = interface_status.get('ipv4_addresses', [])
                            ipv6_addr = interface_status.get('ipv6_addresses', [])

                            mac_address = interface_status.get('mac_address')

                            if ipv4_addr and address_family in ['A', '4']:
                                for address in ipv4_addr:
                                    ip_list.append(address)

                            if ipv6_addr and address_family in ['A', '6']:
                                for address in ipv6_addr:
                                    ip_list.append(address)

                            if ip_list:
                                interface_str = ";".join(ip_list)

                        # Parse WAN network info.
                        already_wrote = False
                        if intf_site_wan_interface_id:
                            logger.info("SWI: %s", intf_site_wan_interface_id)
                            swi = intf_site_wan_interface_id
                            swi_data = swi_id_dict.get(intf_site_wan_interface_id)
                            logger.debug("SWI DUMP: %s", json.dumps(swi_data))
                            lqm_enabled = "Yes" if swi_data.get('lqm_enabled', "") else "No"
                            bw_config_mode = swi_data.get('bw_config_mode', "")
                            if bw_config_mode in ['manual_bwm_disabled']:
                                pcm_enabled = "Yes"
                            else:
                                pcm_enabled = "No"
                            qos_enabled = "Yes" if swi_data.get('bwc_enabled', "") else "No"
                            link_bw_down = swi_data.get('link_bw_down')
                            link_bw_up = swi_data.get('link_bw_up')
                            if link_bw_up:
                                conf_bw_up = "{0:.3f} Mbps".format(link_bw_up)
                            if link_bw_down:
                                conf_bw_down = "{0:.3f} Mbps".format(link_bw_down)

                            swi_name = swi_data.get('name', "")
                            swi_network_id = swi_data.get('network_id', "")
                            swi_label_id = swi_data.get('label_id', "")
                            wan_network_name = id_wannetwork_dict.get(swi_network_id, "")
                            circuit_category = id_circuit_categories.get(swi_label_id, "")
                            security_zone = id_securityzone_dict.get(
                                network_to_security_zone_dict.get(swi, "")
                            )

                            # check for none
                            if security_zone is None:
                                security_zone = ""

                            # print("SWI ID: ", swi)
                            logger.debug("ZONE DICT: %s", json.dumps(id_securityzone_dict, indent=4))
                            logger.debug(
                                "NW -> ZONE DICT: {0}".format(json.dumps(network_to_security_zone_dict, indent=4)))

                            if not swi_name and not wan_network_name:
                                swi_name = "Circuit"
                            elif not swi_name:
                                swi_name = "Circuit to {0}".format(wan_network_name)

                        elif intf_site_wan_interface_ids:
                            # This path writes per SWI - already wrote needs to be set.
                            already_wrote = True
                            for swi in intf_site_wan_interface_ids:
                                logger.info("SWIS: %s", json.dumps(swi, indent=4))
                                swi_data = swi_id_dict.get(swi, {})
                                logger.debug("SWI DUMP: %s", json.dumps(swi_data))

                                lqm_enabled = swi_data.get('lqm_enabled', "")
                                bw_config_mode = swi_data.get('bw_config_mode', "")
                                if bw_config_mode in ['manual_bwm_disabled']:
                                    pcm_enabled = False
                                else:
                                    pcm_enabled = True
                                qos_enabled = swi_data.get('bwc_enabled', "")
                                link_bw_down = swi_data.get('link_bw_down')
                                link_bw_up = swi_data.get('link_bw_up')
                                if link_bw_up:
                                    conf_bw_up = "{0:.3f} Mbps".format(link_bw_up)
                                if link_bw_down:
                                    conf_bw_down = "{0:.3f} Mbps".format(link_bw_down)

                                swi_name = swi_data.get('name', "")
                                swi_network_id = swi_data.get('network_id', "")
                                swi_label_id = swi_data.get('label_id', "")
                                wan_network_name = id_wannetwork_dict.get(swi_network_id, "")
                                circuit_category = id_circuit_categories.get(swi_label_id, "")
                                security_zone = id_securityzone_dict.get(
                                    network_to_security_zone_dict.get(swi, "")
                                )

                                # check for none
                                if security_zone is None:
                                    security_zone = ""

                                # print("SWI ID: ", swi)
                                logger.debug("ZONE DICT: %s", json.dumps(id_securityzone_dict, indent=4))
                                logger.debug(
                                    "NW -> ZONE DICT: {0}".format(json.dumps(network_to_security_zone_dict, indent=4)))

                                if not swi_name and not wan_network_name:
                                    swi_name = "Circuit"
                                elif not swi_name:
                                    swi_name = "Circuit to {0}".format(wan_network_name)

                                # Write to CSV
                                logger.debug("Writing via multiple-SWI CSV function")
                                write_to_csv(interfaces_csv,
                                             # Site Name
                                             site_name,
                                             # Site Type
                                             site_type,
                                             # Site Mode
                                             site_admin_state,
                                             # ION name
                                             element_name,
                                             # Interface name
                                             interface_name,
                                             # Interface used for
                                             used_for,
                                             # Network Policy
                                             site_policyset_name,
                                             # Security Policy
                                             site_security_policyset_name,
                                             # Port Admin State
                                             interface_admin_state,
                                             # MAC Address
                                             mac_address,
                                             # VLAN
                                             vlan_id,
                                             # Address/Mask List
                                             interface_str,
                                             # Config by
                                             intf_ipv4_config_type,
                                             # MTU
                                             interface_mtu,
                                             # Network Context
                                             "",
                                             # Local or Global
                                             "",
                                             # Security Zone
                                             security_zone,
                                             # Circuit Name
                                             swi_name,
                                             # Configured BW Up
                                             conf_bw_up,
                                             # Configured BW Down
                                             conf_bw_down,
                                             # PCM
                                             str(pcm_enabled),
                                             # LQM
                                             lqm_enabled,
                                             # QoS
                                             qos_enabled,
                                             # Circuit Catagory
                                             circuit_category,
                                             # WAN Network Name
                                             wan_network_name,
                                             # Configured NAT address
                                             "" if not intf_conf_nat_addr else intf_conf_nat_addr,
                                             # Configured NAT Port
                                             "" if intf_conf_nat_port == 0 else intf_conf_nat_port,
                                             # Operational State
                                             operational_state,
                                             # Speed
                                             operational_speed,
                                             # Duplex
                                             operational_duplex,
                                             # Link State
                                             operational_link,
                                             # UNIX device name
                                             operational_device)

                        elif intf_attached_lan_networks:
                            # this function will write CSV itself.
                            already_wrote = True
                            for ln_mapping in intf_attached_lan_networks:
                                logger.info("LN: %s", json.dumps(ln_mapping, indent=4))

                                # use seperate ip list for LN
                                ln_ip_list = []
                                ln_network_id = ln_mapping.get('lan_network_id')
                                ln_vlan_id = ln_mapping.get('vlan_id')

                                if ln_vlan_id == 0:
                                    ln_vlan_id = "NATIVE"

                                ln_data = ln_id_dict.get(ln_network_id, {})
                                ln_ipv4_config = ln_data.get('ipv4_config', {})
                                logger.debug("LN DATA: %s", json.dumps(ln_data, indent=4))

                                ipv4_addr = ln_ipv4_config.get('default_routers', [])
                                ln_network_context_id = ln_data.get('network_context_id')
                                ln_scope = ln_data.get('scope')

                                if ln_scope:
                                    global_local = ln_scope.title()
                                else:
                                    global_local = "Unknown"

                                if not ln_network_context_id:
                                    network_context = "Default"
                                else:
                                    network_context = id_network_contexts.get(ln_network_context_id,
                                                                              ln_network_context_id)

                                if ipv4_addr and address_family in ['A', '4']:
                                    for address in ipv4_addr:
                                        ln_ip_list.append(address)

                                if ln_ip_list:
                                    interface_str = ";".join(ln_ip_list)
                                    # save used lan networks for later comparison
                                    site_used_prefixes += ln_ip_list

                                security_zone = id_securityzone_dict.get(
                                    network_to_security_zone_dict.get(ln_network_id, "")
                                )

                                # check for none
                                if security_zone is None:
                                    security_zone = ""

                                # ips on LAN Networks are always static
                                intf_ipv4_config_type = "static"

                                logger.debug("Writing via LAN Networks CSV function")
                                write_to_csv(interfaces_csv,
                                             # Site Name
                                             site_name,
                                             # Site Type
                                             site_type,
                                             # Site Mode
                                             site_admin_state,
                                             # ION name
                                             element_name,
                                             # Interface name
                                             interface_name,
                                             # Interface used for
                                             used_for,
                                             # Network Policy
                                             site_policyset_name,
                                             # Security Policy
                                             site_security_policyset_name,
                                             # Port Admin State
                                             interface_admin_state,
                                             # MAC Address
                                             mac_address,
                                             # VLAN
                                             ln_vlan_id,
                                             # Address/Mask List
                                             interface_str,
                                             # Config by
                                             intf_ipv4_config_type,
                                             # MTU
                                             interface_mtu,
                                             # Network Context
                                             network_context,
                                             # Local or Global
                                             global_local,
                                             # Security Zone
                                             security_zone,
                                             # Circuit Name
                                             swi_name,
                                             # Configured BW Up
                                             conf_bw_up,
                                             # Configured BW Down
                                             conf_bw_down,
                                             # PCM
                                             pcm_enabled,
                                             # LQM
                                             lqm_enabled,
                                             # QoS
                                             qos_enabled,
                                             # Circuit Catagory
                                             circuit_category,
                                             # WAN Network Name
                                             wan_network_name,
                                             # Configured NAT address
                                             "" if not intf_conf_nat_addr else intf_conf_nat_addr,
                                             # Configured NAT Port
                                             "" if intf_conf_nat_port == 0 else intf_conf_nat_port,
                                             # Operational State
                                             operational_state,
                                             # Speed
                                             operational_speed,
                                             # Duplex
                                             operational_duplex,
                                             # Link State
                                             operational_link,
                                             # UNIX device name
                                             operational_device)

                        elif intf_used_for in ['controller'] and ip_list:
                            logger.info("CONTROLLER: %s", ip_list)
                        elif site_type in ['DC'] and ip_list:
                            logger.info("PEERING: %s", ip_list)
                        elif site_type:
                            logger.info("UNCONFIGURED: %s, %s, %s, %s",
                                        interface_name,
                                        site_type,
                                        mac_address)

                        # if not handled by a function above, write CSV.
                        if not already_wrote:
                            # Write to CSV
                            logger.debug("Writing via common CSV function")
                            write_to_csv(interfaces_csv,
                                         # Site Name
                                         site_name,
                                         # Site Type
                                         site_type,
                                         # Site Mode
                                         site_admin_state,
                                         # ION name
                                         element_name,
                                         # Interface name
                                         interface_name,
                                         # Interface used for
                                         used_for,
                                         # Network Policy
                                         site_policyset_name,
                                         # Security Policy
                                         site_security_policyset_name,
                                         # Port Admin State
                                         interface_admin_state,
                                         # MAC Address
                                         mac_address,
                                         # VLAN
                                         vlan_id,
                                         # Address/Mask List
                                         interface_str,
                                         # Config by
                                         intf_ipv4_config_type,
                                         # MTU
                                         interface_mtu,
                                         # Network Context
                                         "",
                                         # Local or Global
                                         "",
                                         # Security Zone
                                         security_zone,
                                         # Circuit Name
                                         swi_name,
                                         # Configured BW Up
                                         conf_bw_up,
                                         # Configured BW Down
                                         conf_bw_down,
                                         # PCM
                                         pcm_enabled,
                                         # LQM
                                         lqm_enabled,
                                         # QoS
                                         qos_enabled,
                                         # Circuit Catagory
                                         circuit_category,
                                         # WAN Network Name
                                         wan_network_name,
                                         # Configured NAT address
                                         "" if not intf_conf_nat_addr else intf_conf_nat_addr,
                                         # Configured NAT Port
                                         "" if intf_conf_nat_port == 0 else intf_conf_nat_port,
                                         # Operational State
                                         operational_state,
                                         # Speed
                                         operational_speed,
                                         # Duplex
                                         operational_duplex,
                                         # Link State
                                         operational_link,
                                         # UNIX device name
                                         operational_device)

                        # iterate bar and counter.
                        barcount += 1
                        pbar.update(barcount)

            # validate prefix matches
            logger.debug("SITE ALL PREFIXES: %s", json.dumps(site_all_prefixes, indent=4))
            logger.debug("SITE USED PREFIXES: %s", json.dumps(site_used_prefixes, indent=4))
            unattached_prefixes = [prefix for prefix in site_all_prefixes if prefix not in site_used_prefixes]

            # Some prefixes left over that need to be written.
            if unattached_prefixes:
                logger.debug("Writing via Unattached Prefix logic")
                interface_str = interface_str = ";".join(unattached_prefixes)
                write_to_csv(interfaces_csv,
                             # Site Name
                             site_name,
                             # Site Type
                             site_type,
                             # Site Mode
                             site_admin_state,
                             # ION name
                             "",
                             # Interface name
                             "",
                             # Interface used for
                             "Site IP Prefixes",
                             # Network Policy
                             site_policyset_name,
                             # Security Policy
                             site_security_policyset_name,
                             # Port Admin State
                             "",
                             # MAC Address
                             "",
                             # VLAN
                             "",
                             # Address/Mask List
                             interface_str,
                             # Config by
                             "",
                             # MTU
                             "",
                             # Network Context
                             "",
                             # Local or Global
                             "",
                             # Security Zone
                             "",
                             # Circuit Name
                             "",
                             # Configured BW Up
                             "",
                             # Configured BW Down
                             "",
                             # PCM
                             "",
                             # LQM
                             "",
                             # QoS
                             "",
                             # Circuit Catagory
                             "",
                             # WAN Network Name
                             "",
                             # Configured NAT address
                             "",
                             # Configured NAT Port
                             0,
                             # Operational State
                             "",
                             # Speed
                             "",
                             # Duplex
                             "",
                             # Link State
                             "",
                             # UNIX device name
                             "")

    # finish after iteration.
    pbar.finish()
    # logout
    cgx_session.interactive.logout()
    sys.exit()
