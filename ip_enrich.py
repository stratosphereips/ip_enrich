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
        for key in self.vtdata:
            #print(f'Key: {key}')
            #print(self.vtdata[key])
            #print
            if 'detected_downloaded_samples' in key:
                self.processedvtdata['detected_downloaded_samples'] = self.vtdata[key]
            elif 'as_owner' in key:
                self.processedvtdata['as_owner'] = self.vtdata[key]
            elif 'detected_referrer_samples' in key:
                self.processedvtdata['detected_referrer_samples'] = self.vtdata[key]
            elif 'country' in key:
                self.processedvtdata['country'] = self.vtdata[key]
            elif 'detected_urls' in key:
                self.processedvtdata['detected_urls'] = self.vtdata[key]
            elif 'detected_communicating_samples' in key:
                self.processedvtdata['detected_communicating_samples'] = self.vtdata[key]
            elif 'resolutions' in key:
                self.processedvtdata['resolutions'] = self.vtdata[key]
                # Sort and reverse the keys
                # Store the resolutions in our dictionary so we can sort them
                temp_dict = {}
                for resolution_item in self.processedvtdata['resolutions']:
                    temp_dict[resolution_item['last_resolved']] = resolution_item['hostname']
                # Sort them by datetime and convert to list
                self.processedvtdata['resolutions'] = sorted(temp_dict.items(), reverse=True)
        del self.vtdata

    def __repr__(self):
        """
        Print the object
        """
        pp = pprint.PrettyPrinter(width=60, compact=True)
        output = f'IP: {self.ip}\n'

        # Print vt resolutions. Is a list
        output += f'VT Resolutions (top {args.amount_to_print}):\n'
        for count, resolution_tuple in enumerate(self.processedvtdata['resolutions']):
            output += f'\t{resolution_tuple[0]}: {resolution_tuple[1]}\n'
            if count >= args.amount_to_print:
                break
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
    


