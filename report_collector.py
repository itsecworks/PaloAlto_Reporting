#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author: Ist wurst...
#
# Description:
# -------------
#
# This script collects custom reports defined in the script and with custom filter where the filter data is used from an external file.
# The external file contains the following data fields in csv format:
#
#    location_name = data_list[0].strip()
#    ip_net_name = data_list[1].strip()
#    ip_net = data_list[2].strip()
#    ip_net_vlanid = data_list[3].strip()
#    ip_net_function = data_list[4].strip()
#    ip_net_zone = data_list[5].strip()
#
# Output:
# -------
#
# The output is an nljson (new line separated json file) that can be easily imported to elasticsearch for analisys
# and dashboards can be created easily.
#
# Palo Alto report enrichments:
# -----------------------------
#
#  1. the following informations added to each line of the report:
#
#    location_name 
#    ip_net_name 
#    ip_net 
#    ip_net_vlanid 
#    ip_net_function 
#    ip_net_zone 
# 
#  2. From the url reports the url_domain is accurately separated to URL's subdomain, domain, and public suffix, using the Public Suffix List (PSL)
#
#  3. Resolves internal and external source and destination IPs - just in case the panorama is not configured for that
#     and marks the unresolvable IPs. The DNS resolution is multi-threaded to not loose time while collecting reports from panorama.

import requests
import argparse
import logging
import sys, getopt
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from threading import Thread
import socket
import json
from urllib.parse import urlparse, parse_qs
import tldextract

def get_api(host, params, log=False):
    # script_path = os.path.dirname(__file__)
    # CA_file = "Palo_Alto_Networks_Inc-Root-CA_G1.pem"
    # CA_path = os.path.join(script_path, CA_file)

    request_timeout = 20

    url: str = 'https://' + host + '/api/'

    if log:
        logging.info('Trying to access host: %s with cmd: %s', host, params['cmd'])

    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    print('xml api started at: ', now_str)

    try:
        # response = requests.post(url, timeout=request_timeout, verify=CA_path)
        response = requests.post(url, params=params, timeout=request_timeout, verify=False)
    except requests.exceptions.RequestException as e:
        if log:
            logging.error('We run in that problem: %s', e)
        raise SystemExit(e)

    if response.status_code != 200:
        if log:
            logging.error('Cannot access the website, status code: %s', response.status_code)
            logging.error('reply from the website:\n%s\n', response.text)
        raise SystemExit(str(response.status_code) + " - " + response.text)
    else:
        if log:
            logging.info('response from website:\n\n%s\n', response.text)
        return response.text


def get_report(host, hash_key, report_name, report, start_time, ip_network, log=False):
    # reportstarturl    = '/api/?type=report&async=yes&report_type=custom&report_name='
    # reportgeturl    = '/api/?type=report&action=get&job-id='

    argssetrep = {
        'type': 'config',
        'action': 'set',
        'xpath': '/config/shared/reports/entry[@name=\'' + report_name + '\']',
        'element': report,
        'key': hash_key
    }

    argsinitrep = {
        'type': 'report',
        'async': 'yes',
        'key': hash_key,
        'reporttype': 'custom',
        'reportname': report_name
    }
    argsgetrep = {
        'type': 'report',
        'action': 'get',
        'job-id': '1',
        'key': hash_key
    }

    # 1. create the report
    xml_response = get_api(host, argssetrep, log)

    if log:
        logging.info("api xml output Original: \n" + xml_response.decode("utf-8"))

    time.sleep(5)

    # 2. start the report
    xml_response = get_api(host, argsinitrep, log)

    if log:
        logging.info("api xml output Original: \n" + xml_response.decode("utf-8"))

    root_report = ''
    if xml_response:
        time.sleep(10)
        root = ET.fromstring(xml_response)
        for entry in root.findall('./result/msg/line'):
            attribval = entry.text
            if attribval.find('jobid') != -1:
                jobid = attribval.split()[-1]
                argsgetrep['job-id'] = jobid

                # 3. loop till the report is ready. The status will be change from ACT to FIN.
                report_not_ready = True
                while report_not_ready:
                    xml_response2 = get_api(host, argsgetrep, log)
                    root_report = ET.fromstring(xml_response2)
                    xpath = './result/job/status'
                    if root_report.find(xpath) is None:
                        if "No such report" in (ET.tostring(root_report)).decode("utf-8"):
                            print(jobid, "- report disappeared, restart report generation...")
                            xml_response = get_api(host, argsinitrep, log)
                            report_not_ready = False
                        else:
                            print("We got problem: ", (ET.tostring(root_report)).decode("utf-8"))
                            xml_response = get_api(host, argsinitrep, log)
                            report_not_ready = False
                    if root_report.find(xpath) is not None and root_report.find(xpath).text == "FIN":
                        report_not_ready = False
                    else:
                        time.sleep(20)

            else:
                root_report = "I cannot find the jobid for the report. Contact the Firewall Administrator!"
                sys.exit()

        return root_report

    else:
        raise Exception("The root cause of the problem is there is no jobid or something...")

def resolveDns(ips):
    for ip in ips:
        try:
            result = "{h}: {a}\n".format(h=ip, a=socket.gethostbyaddr(ip)[0])
        except Exception as e:
            result = "{h}: {a}\n".format(h=ip, a=str(e).replace(" ", "_"))
        resolved_ips.append(result)

def main(argv):

    # working folder is set with the file_path the ip network csv must be here, see default_ipnetworks variable below.
    file_path = 'C:/Users/dakos/Downloads/'
    timeframe = "last-30-days"
    # timeframe = "last-7-days"
    default_panorama = 'panorama.internal'
    default_key = 'LUFRPT1....lMjcwd2Ftc3ZwaE80N....'
    default_report_name = 'hazardous_rules_site_x'
    default_ipnetworks = 'site_x_ipnetworks.csv'
    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    default_start_time = now_str
    report_query_static = "((rule eq 'hazardous-rulename') or (rule eq 'hazardous-rulename-highports')) and (action eq alert or action eq allow) and "
    
    # 1. check the arguments
    parser = argparse.ArgumentParser(description='Palo Alto Report Collector .',
                                     epilog="And that's how you collect custom reports to ELK...")
    parser.add_argument('-v', '--version',
                        action='version', version='%(prog)s 1.0')
    parser.add_argument('-l', '--log',
                        action='store_true',
                        default=False,
                        help='switch logging on',
                        dest='log')
    parser.add_argument('-p', '--panorama',
                        help='IP or hostname of the Palo Alto Panorama',
                        dest='panorama',
                        default=default_panorama)
    parser.add_argument('-k', '--hashkey',
                        help='Password hash for the logon on Palo Alto Panorama',
                        dest='hashkey',
                        default=default_key)
    parser.add_argument('-n', '--reportname',
                        help='The Name of the report in Panorama',
                        dest='reportname',
                        default=default_report_name)
    parser.add_argument('-r','--report',
                        help='palo alto custom report in xml format. will be available later...dont use it here',
                        dest='report')
    parser.add_argument('-i', '--ipnetworks',
                        help='csv file with the devices and ip networks, used in filter of custom report',
                        dest='ipnetworks',
                        default=default_ipnetworks)
    parser.add_argument('-s', '--starttime',
                        nargs='?',
                        help='start time for the report time selection. default is yesterday.',
                        dest='starttime',
                        default=default_start_time)
    args = parser.parse_args()

    # logging
    if args.log:
        logging.basicConfig(level=logging.INFO,
                            filename='prtg-info.log',  # log to this file
                            format='%(asctime)s %(message)s')  # include timestamp
        logging.info("Start Logging...")

    # set the file for ip networks from argument or default value if argument is not set
    file_ipnet_path = file_path + args.ipnetworks

    report_traffic = '''\
    <type>
      <panorama-traffic>
        <sortby>repeatcnt</sortby>
        <aggregate-by>
          <member>device_name</member>
          <member>src</member>
          <member>dst</member>
          <member>dport</member>
          <member>app</member>
          <member>category-of-app</member>
          <member>subcategory-of-app</member>
        </aggregate-by>
        <values>
          <member>bytes</member>
          <member>bytes_received</member>
          <member>bytes_sent</member>
        </values>
      </panorama-traffic>
    </type>
    <period>{rep_timeframe}</period>
    <topn>10000</topn>
    <topm>10</topm>
    <caption>report_name_test_TRAFFIC</caption>\
    '''.format(rep_timeframe=timeframe)

    report_url = '''\
    <type>
      <panorama-urlsum>
        <sortby>repeatcnt</sortby>
        <aggregate-by>
          <member>device_name</member>
          <member>src</member>
          <member>dst</member>
          <member>dport</member>
          <member>url_domain</member>
          <member>app</member>
          <member>category-of-app</member>
          <member>subcategory-of-app</member>
          <member>url_category_list</member>
        </aggregate-by>
        <values>
          <member>repeatcnt</member>
        </values>
      </panorama-urlsum>
    </type>
    <period>{rep_timeframe}</period>
    <topn>10000</topn>
    <topm>10</topm>
    <caption>report_name_test_URL</caption>\
    '''.format( rep_timeframe=timeframe)

    with open(file_ipnet_path) as file_in:
        lines = file_in.readlines()
        # Iterate over the IP Networks from CSV file
        for line in lines[1:]:

            data_list = line.split(',')
            ip_net = data_list[2].strip()
            if "/29" not in ip_net and "/30" not in ip_net and "/32" not in ip_net:
                location_name = data_list[0].strip()
                ip_net_name = data_list[1].strip()
                ip_net_vlanid = data_list[3].strip()
                ip_net_function = data_list[4].strip()
                ip_net_zone = data_list[5].strip()

                report_query_dynamic = "(addr.src in \'{ipnetwork}\')".format(ipnetwork=ip_net)
                report_query = report_query_static + report_query_dynamic
                report_traffic_full = report_traffic + "\n<query>" + report_query + "</query>"
                report_url_full = report_url + "\n<query>" + report_query + "</query>"
                report_traffic_full.replace('\n', '')
                report_url_full.replace('\n', '')

                input_xml_reports = [report_traffic_full, report_url_full]
                # Iterate over the reports with each IP Network. One traffic and one url report is used now.
                for input_xml_report in input_xml_reports:
                    print(input_xml_report)

                    output = ''
                    if "panorama-traffic" in input_xml_report:
                        report_name = args.reportname + "_traffic"
                        filename = file_path + report_name

                    elif "panorama-urlsum" in input_xml_report:
                        report_name = args.reportname + "_url"
                        filename = file_path + report_name

                    file = open(filename, "a")
                    report_xml = get_report(args.panorama, args.hashkey, report_name, input_xml_report,
                                            args.starttime, ip_net, args.log)

                    #if report has no data write an entry with zero bytes
                    report_str = (ET.tostring(report_xml)).decode("utf-8")
                    if "<src>" not in report_str:
                        print("empty report: ", location_name, ip_net)
                        element_dict = {}
                        element_dict["ip_network"] = ip_net
                        element_dict["date"] = args.starttime
                        element_dict["location_name"] = location_name
                        element_dict["ip_network_function"] = ip_net_function
                        element_dict["ip_network_name"] = ip_net_name
                        element_dict["ip_network_vlanid"] = ip_net_vlanid
                        element_dict["ip_network_zone"] = ip_net_zone
                        # if report is from panorama traffic, add byte values
                        if "panorama-traffic" in input_xml_report:
                            element_dict["bytes"] = 0
                            element_dict["bytes_sent"] = 0
                            element_dict["bytes_received"] = 0
                        # if report is from panorama url, add repeatcnt value
                        elif "panorama-urlsum" in input_xml_report:
                            element_dict["repeatcnt"] = 0
                        output += json.dumps(element_dict) + '\n'

                    # if report has data write it to the csv file
                    else:
                        src_ips = []
                        global resolved_ips
                        resolved_ips = []
                        dst_ips = []

                        # data enrichment with new fields:
                        for entry2 in report_xml.findall('./result/report/entry'):
                            # timestamp
                            date_element = ET.Element("date")
                            date_element.text = args.starttime
                            entry2.insert(0, date_element)
                            # ip_network
                            ip_net_element = ET.Element("ip_network")
                            ip_net_element.text = ip_net
                            entry2.insert(0, ip_net_element)
                            # location
                            location_element = ET.Element("location_name")
                            location_element.text = location_name
                            entry2.insert(0, location_element)
                            # ip network function
                            net_function_element = ET.Element("ip_network_function")
                            net_function_element.text = ip_net_function
                            entry2.insert(0, net_function_element)
                            # ip network name
                            ip_net_name_element = ET.Element("ip_network_name")
                            ip_net_name_element.text = ip_net_name
                            entry2.insert(0, ip_net_name_element)
                            # ip network vlanid
                            ip_net_vlanid_element = ET.Element("ip_network_vlanid")
                            ip_net_vlanid_element.text = ip_net_vlanid
                            entry2.insert(0, ip_net_vlanid_element)
                            # ip network zone
                            ip_net_zone_element = ET.Element("ip_network_zone")
                            ip_net_zone_element.text = ip_net_zone
                            entry2.insert(0, ip_net_zone_element)
                            # registered url domain and subdomain for URL report only. The field ur_domain exists only in url reports
                            if entry2.find("url_domain") is not None:
                                url_domain = entry2.find("url_domain").text
                                parsed_url = urlparse("https://" + url_domain)
                                extracted_url = tldextract.extract(parsed_url.hostname)
                                registered_domain = f"{extracted_url.domain}.{extracted_url.suffix}"
                                registered_subdomain = extracted_url.subdomain
                                reg_domain_element = ET.Element("registered_domain")
                                reg_domain_element.text = registered_domain
                                sub_domain_element = ET.Element("registered_subdomain")
                                sub_domain_element.text = registered_subdomain
                                entry2.insert(0, reg_domain_element)
                                entry2.insert(0, sub_domain_element)
                            # collect ips for later resolution
                            src_ips.append(entry2.find('src').text)
                            dst_ips.append(entry2.find('dst').text)

                        # data enrichment with 1 field update: resolved-src
                        # here we resolve the src ip to dns name if exists. it is multi-threaded.
                        threads = list()

                        chunk_size = 3
                        for i in range(0, len(src_ips), chunk_size):
                            src_ip_chunk = src_ips[i:i + chunk_size]
                            x = Thread(target=resolveDns, args=(src_ip_chunk,))
                            threads.append(x)
                            x.start()

                        for src_ip_chunk, thread in enumerate(threads):
                            thread.join()

                        # data enrichment with 1 field update: resolved-dst
                        # here we resolve the dst ip to dns name if exists. it is multi-threaded.
                        threads = list()

                        chunk_size = 3
                        for i in range(0, len(dst_ips), chunk_size):
                            dst_ip_chunk = dst_ips[i:i + chunk_size]
                            x = Thread(target=resolveDns, args=(dst_ip_chunk,))
                            threads.append(x)
                            x.start()

                        for dst_ip_chunk, thread in enumerate(threads):
                            thread.join()

                        # write the data with resolved names from xml to json
                        element_dict = {}
                        for entry2 in report_xml.findall('./result/report/entry'):
                            #fill back the resolved-src field
                            src_ip = entry2.find('src').text
                            for element in resolved_ips:
                                if src_ip in element:
                                    entry2.find('resolved-src').text = (element.split(':')[1]).strip()

                            # fill back the resolved-dst field
                            dst_ip = entry2.find('dst').text
                            for element in resolved_ips:
                                if dst_ip in element:
                                    entry2.find('resolved-dst').text = (element.split(':')[1]).strip()

                            # export modified xml entry to json
                            for element_xml in entry2:
                                element_dict[element_xml.tag] = element_xml.text

                            output += json.dumps(element_dict) + '\n'

                    file.write(output)
                    file.close()

if __name__ == "__main__":
    main(sys.argv[1:])
