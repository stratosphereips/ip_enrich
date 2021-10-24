#!/usr/bin/env python3
# Stratosphere script to enrich an IP address with metadata

import argparse
import requests
#from requests.auth import HTTPBasicAuth
import datetime
import collections
#import re
import sys
import json
from json import JSONDecodeError
import urllib3
import os
import pprint
import time
import certifi


class IP():
    """
    Class to manage all the IP data
    """
    def __init__(self, ip):
        self.ip = ip
        self.vtkey = None
        self.http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
        try:
            with open('vt_credentials', "r") as f:
                self.key = f.read(64)
        except FileNotFoundError:
            self.print("The file with API key (vt_credentials) could not be loaded. VT module is stopping.")
            return False

    def getVT(self):
        # Get VirusTotal data
        params = {'apikey': self.key}
        self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params.update({'ip': self.ip})

        while True:
            try:
                response = self.http.request("GET", self.url, fields=params)
                break
            except urllib3.exceptions.MaxRetryError:
                self.print("Network is not available, waiting 10s")
                time.sleep(10)

        if response.status != 200:
            # 204 means Request rate limit exceeded. You are making more requests
            # than allowed. You have exceeded one of your quotas (minute, daily or monthly).
            if response.status == 204:
                print("Asking too fast... wait a little and retry.")
            # 403 means you don't have enough privileges to make the request or wrong API key
            elif response.status == 403:
                # don't add to the api call queue because the user will have to restart slips anyway
                # to add a correct API key and the queue wil be erased
                self.print("Please check that your API key is correct.")
            else:
                # if the query was unsuccessful but it is not caused by API limit, abort (this is some unknown error)
                # X-Api-Message is a comprehensive error description, but it is not always present
                if "X-Api-Message" in response.headers:
                    message = response.headers["X-Api-Message"]
                    # Reason is a much shorter description ("Forbidden"), but it is always there
                else:
                    message = response.reason
                    print(f'VT API returned an unexpected code: {str(response.status)}. Message: {message}')

            # report that API limit is reached, wait one minute and try again
            self.print("Status code is " + str(response.status) + " at " + str(time.asctime()) + ", query id: " + str(
                self.counter), 0,2)
            # return empty dict because api call isn't successful
            data = {}
        else:
            # query successful
            data = json.loads(response.data)
            if type(data) == list:
                # this is an empty list, vt dometimes returns it with status code 200
                data = {}
        # Everything fine
        self.vtdata = data

    def processVT(self):
        # Process vt data
        self.processedvtdata = {}
        # Default to no data
        self.processedvtdata['detected_downloaded_samples'] = 'None'
        self.processedvtdata['as_owner'] = 'None'
        self.processedvtdata['country'] = 'None'
        self.processedvtdata['detected_urls'] = 'None'
        self.processedvtdata['detected_communicating_samples'] = 'None'
        self.processedvtdata['detected_referrer_samples'] = 'None'
        self.processedvtdata['resolutions'] = 'None'
        for key in self.vtdata:
            if 'detected_downloaded_samples' in key:
                if self.vtdata[key]:
                    self.processedvtdata['detected_downloaded_samples'] = self.vtdata[key]
                    # Sort and reverse the keys
                    # Store the samples in our dictionary so we can sort them
                    temp_dict = {}
                    for detected_dowload_item in self.processedvtdata['detected_downloaded_samples']:
                        temp_dict[detected_dowload_item['date']] = [detected_dowload_item['positives'], detected_dowload_item['total'], detected_dowload_item['sha256']]
                    # Sort them by datetime and convert to list
                    self.processedvtdata['detected_downloaded_samples'] = sorted(temp_dict.items(), reverse=True)
            elif 'as_owner' in key:
                if self.vtdata[key]:
                    self.processedvtdata['as_owner'] = self.vtdata[key]
            elif 'asn' in key:
                if self.vtdata[key]:
                    self.processedvtdata['asn'] = self.vtdata[key]
            elif 'detected_referrer_samples' in key:
                if self.vtdata[key]:
                    self.processedvtdata['detected_referrer_samples'] = self.vtdata[key]
                    # {'positives': 1, 'total': 53, 'sha256': '5d4c6801a5d1c9e4d3f8317242723e17eefc7fbdfcf1b0a99fbc5b92b4b83631'}
                    # Sort and reverse the keys
                    # Store the samples in our dictionary so we can sort them
                    temp_dict = {}
                    for detected_referrer_item in self.processedvtdata['detected_referrer_samples']:
                        temp_dict[detected_referrer_item['sha256']] = [detected_referrer_item['positives'], detected_referrer_item['total']]
                    # Sort them by datetime and convert to list
                    self.processedvtdata['detected_referrer_samples'] = sorted(temp_dict.items(), reverse=True)
            elif 'country' in key:
                if self.vtdata[key]:
                    self.processedvtdata['country'] = self.vtdata[key]
            elif 'detected_urls' in key:
                if self.vtdata[key]:
                    self.processedvtdata['detected_urls'] = self.vtdata[key]
                    # Sort and reverse the keys
                    # Store the urls in our dictionary so we can sort them
                    temp_dict = {}
                    for detected_url_item in self.processedvtdata['detected_urls']:
                        if type(detected_url_item) == dict:
                            # Some items are dicts
                            # {'url': 'http://willbshots.com/images', 'positives': 11, 'total': 91, 'scan_date': '2021-10-24 08:37:40'}
                            temp_dict[detected_url_item['scan_date']] = [detected_url_item['url'], detected_url_item['positives'], detected_url_item['total']]
                        elif type(detected_url_item) == list:
                            # an item is usually
                            # ['http://alltidrenbil.no/', '09151b5f41955ac8eafe5296408c6407e69538a9d3c1546386d2b3e5dbdbe603', 0, 91, '2021-10-24 09:08:58']
                            temp_dict[detected_url_item[4]] = [detected_url_item[0], detected_url_item[2], detected_url_item[3]]
                    # Sort them by datetime and convert to list
                    self.processedvtdata['detected_urls'] = sorted(temp_dict.items(), reverse=True)
            elif 'detected_communicating_samples' in key:
                if self.vtdata[key]:
                    self.processedvtdata['detected_communicating_samples'] = self.vtdata[key]
                    # Sort and reverse the keys
                    # Store the samples in our dictionary so we can sort them
                    temp_dict = {}
                    for detected_communicating_item in self.processedvtdata['detected_communicating_samples']:
                        temp_dict[detected_communicating_item['date']] = [detected_communicating_item['positives'], detected_communicating_item['total'], detected_communicating_item['sha256']]
                    # Sort them by datetime and convert to list
                    self.processedvtdata['detected_communicating_samples'] = sorted(temp_dict.items(), reverse=True)
            elif 'resolutions' in key:
                if self.vtdata[key]:
                    self.processedvtdata['resolutions'] = self.vtdata[key]
                    # Sort and reverse the keys
                    # Store the resolutions in our dictionary so we can sort them
                    temp_dict = {}
                    for resolution_item in self.processedvtdata['resolutions']:
                        temp_dict[resolution_item['last_resolved']] = resolution_item['hostname']
                    # Sort them by datetime and convert to list
                    self.processedvtdata['resolutions'] = sorted(temp_dict.items(), reverse=True)
            elif 'response_code' in key:
                if self.vtdata[key]:
                    self.processedvtdata['response_code'] = self.vtdata[key]
            elif 'verbose_msg' in key:
                if self.vtdata[key]:
                    self.processedvtdata['verbose_msg'] = self.vtdata[key]
            else:
                # Unknown key
                print(f'Unknown Key: {key}')
                print(self.vtdata[key])
        del self.vtdata

    def __repr__(self):
        """
        Print the object
        """
        pp = pprint.PrettyPrinter(width=60, compact=True)
        output = f'IP: {self.ip}. Country: {self.processedvtdata["country"]}. AS Org: {self.processedvtdata["as_owner"]}\n'
        
        # Print vt resolutions. Is a list
        if self.processedvtdata['resolutions'] != 'None':
            output += f'VT Resolutions (top {args.amount_to_print}, sorted by datetime):\n'
            for count, resolution_tuple in enumerate(self.processedvtdata['resolutions']):
                if count >= args.amount_to_print:
                    break
                output += f'\t{resolution_tuple[0]}: {resolution_tuple[1]}\n'

        # Print vt urls. Is a list
        if self.processedvtdata['detected_urls'] != 'None':
            print(self.processedvtdata['detected_urls'])
            output += f'VT URLs (top {args.amount_to_print}, sorted by datetime):\n'
            for count, url_tuple in enumerate(self.processedvtdata['detected_urls']):
                if count >= args.amount_to_print:
                    break
                output += f'\t{url_tuple[0]}: {url_tuple[1][0]}. Positives: {url_tuple[1][1]}/{url_tuple[1][2]}\n'

        # Print vt detected communicating samples. Is a list
        if self.processedvtdata['detected_communicating_samples'] != 'None':
            output += f'VT Detected Communicating Samples (top {args.amount_to_print}, sorted by datetime):\n'
            for count, communcating_tuple in enumerate(self.processedvtdata['detected_communicating_samples']):
                if count >= args.amount_to_print:
                    break
                output += f'\t{communcating_tuple[0]}: Positives: {communcating_tuple[1][0]}, Total: {communcating_tuple[1][1]}, SHA256: {communcating_tuple[1][2]}\n'

        # Print vt detected downloaded samples. Is a list
        if self.processedvtdata['detected_downloaded_samples'] != 'None':
            output += f'VT Detected Downloaded Samples (top {args.amount_to_print}, sorted by datetime):\n'
            for count, detected_tuple in enumerate(self.processedvtdata['detected_downloaded_samples']):
                if count >= args.amount_to_print:
                    break
                output += f'\t{detected_tuple[0]}: Positives: {detected_tuple[1][0]}, Total: {detected_tuple[1][1]}, SHA256: {detected_tuple[1][2]}\n'

        # Print vt referrer downloaded samples. Is a list
        if self.processedvtdata['detected_referrer_samples'] != 'None':
            output += f'VT Detected Referrer Samples (top {args.amount_to_print}, sorted by sha):\n'
            for count, referrer_tuple in enumerate(self.processedvtdata['detected_referrer_samples']):
                if count >= args.amount_to_print:
                    break
                output += f'\t{referrer_tuple[0]}: Positives: {referrer_tuple[1][0]}, Total: {referrer_tuple[1][1]}\n'

        return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Stratosphere script to enrich an IP address with metadata.")
    parser.add_argument('-o', dest='output', help='Output a log file. Json', action='store_true', required=False)
    parser.add_argument('-v', dest='verbosity', help='Verbosity level.', default=1, required=False, type=int)
    parser.add_argument('-i', dest='ip', help='IP to enrich.', default=1, required=True, type=str)
    parser.add_argument('-m', dest='amount_to_print', help='How many lines to print per catetory max.', default=10, required=False, type=int)

    args = parser.parse_args()

    # Check if is a real ip or not
    ipaddress = args.ip
    ipobj = IP(ipaddress)

    # Contact VT and get data
    ipobj.getVT()
    # Process VT data
    ipobj.processVT()

    print(ipobj)
    


