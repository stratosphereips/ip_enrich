#!/usr/bin/env python3
# Stratosphere script to enrich an IP address with metadata

import argparse
import requests
import datetime
import json
from json import JSONDecodeError
import urllib3
import os
import pprint
import time
import certifi
import socket
import sys
import subprocess
import shodan
from shodan.exception import APIError


class IP():
    """
    Class to manage all the IP data
    """
    def __init__(self, ip, amount_to_print=10, verbose=10, labelfile=''):
        self.ip = ip
        self.amount_to_print = amount_to_print
        self.vtkey = None
        self.data = []
        self.labelfile = labelfile
        self.http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
        # Create the DB
        self.create_folder()
        try:
            file = os.path.expanduser("~") + '/.ip_enrich/vt_credentials'
            with open(file, "r") as f:
                self.vtkey = f.read(64)
            self.vtapi = True
        except FileNotFoundError:
            print("The file with API keys of VirusTotal could not be loaded.")
            print("Create the file ~/.ip_enrich/vt_credentials, and add the API string.")
            self.vtapi = False
            # It may be possible to use VT without credentials, not impemented yet
            sys.exit(-1)

        try:
            file = os.path.expanduser("~") + '/.ip_enrich/shodan_credentials'
            with open(file, "r") as f:
                key = str(f.read(33)).strip() 
                self.shodanobj = shodan.Shodan(key)
            self.shodanapi = True
        except FileNotFoundError:
            print("The file with API keys of Shodan could not be loaded.")
            print("Create the file ~/.ip_enrich/shodan_credentials, and add the API string.")
            self.shodanapi = False
            # It may be possible to use VT without credentials, not impemented yet
            sys.exit(-1)

        try:
            file = os.path.expanduser("~") + '/.ip_enrich/pt_credentials'
            with open(file, "r") as f:
                self.ptuser = f.readline().split(' =')[1].strip()
                self.ptkey = f.readline().split(' =')[1].strip()
            self.ptapi = True
        except FileNotFoundError:
            print("The file with API keys of PassiveTotal could not be loaded.")
            print("Create a file in ~/.ip_enrich/pt_credentials, and add the following data.")
            print('\tRiskIQ_email = <email>')
            print('\tRiskIQ_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
            print('Go here for a free account https://community.riskiq.com/login')
            self.ptapi = False
            # It is not possible to use PT without credentials
            sys.exit(-1)

    def create_folder(self):
        """
        Create the folder for the DB and credentials
        """
        path = os.path.expanduser('~') + "/.ip_enrich/"
        # Does it exist already?
        if os.path.isdir(path):
            return True
        try:
            os.mkdir(path)
            return True
        except Exception as e:
            print (f"Creation of the directory {path} failed")
            print (f"Error {e}")
            return False

    def getAll(self):
        """
        Get and process all the data
        """
        # Get VT
        self.getVT()
        # Process VT data
        self.processVT()
        # Get reverse DNS
        self.getRDNS()
        # Get passivetotal
        self.getPT()
        # Get Geolocation
        self.getGeo()
        # Get Shodan
        self.getShodan()

    def getGeo(self):
        """
        Get the geo location from ip-api.com

        """
        command = f'curl -s -m 5 http://ip-api.com/json/' + self.ip
        result = subprocess.run(command.split(), capture_output=True)
        data = result.stdout.decode("utf-8").replace('\n','')
        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            # Error from ip-api.com
            data = None
        if data:
            # {"status":"success","country":"Yemen","countryCode":"YE","region":"SA","regionName":"Amanat Alasimah","city":"Sanaa","zip":"","lat":15.3522,"lon":44.2095,"timezone":"Asia/Aden","isp":"Public Telecommunication Corporation","org":"YemenNet","as":"AS30873 Public Telecommunication Corporation","query":"134.35.218.63"}
            self.geodata = data

    def getVT(self):
        # Get VirusTotal data
        if not self.vtapi:
            return False
        params = {'apikey': self.vtkey}
        self.vturl = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params.update({'ip': self.ip})

        while True:
            try:
                response = self.http.request("GET", self.vturl, fields=params)
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

    def getRDNS(self):
        """
        Get the reverse DNS
        """
        self.reversedns = ''
        try:
            if self.ip:
                # works with both ipv4 and ipv6
                reverse_dns = socket.gethostbyaddr(self.ip)[0]
                # if there's no reverse dns record for this ip, reverse_dns will be an ip.
                if ':' in self.ip:
                    socket_type = socket.AF_INET6
                else:
                    socket_type = socket.AF_INET

                try:
                    # reverse_dns is an ip and there's no reverse dns, don't store
                    socket.inet_pton(socket_type, reverse_dns)
                    return False
                except socket.error:
                    # all good, store it
                    self.reversedns = reverse_dns
        except (socket.gaierror, socket.herror, OSError):
            # not an ip or multicast, can't get the reverse dns record of it
            return False

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

    def getPTBL(self):
        """
        Get passive total black list data
        NOT WORKING BECAUSE WE DONT HAVE THE AUTH API
        """
        if not self.ptapi:
            return False
        command = "curl -m 25 --insecure -s -u " + self.ptuser + ":" + self.ptkey + " 'https://api.riskiq.net/v0/blacklist/lookup?url=" + self.ip + "'"

        temp = os.popen(command).read()
        try:
            self.processedptbl = json.loads(temp)
            print(self.processedptbl)
            """
            self.processedptbl_results = None
            # Sort and reverse the keys
            # Store the samples in our dictionary so we can sort them
            temp_dict = {}
            for pt_results in self.processedptdata['results']:
                temp_dict[pt_results['lastSeen']] = [pt_results['firstSeen'], pt_results['resolve'], pt_results['collected']]
            # Sort them by datetime and convert to list
            self.processedptdata_results = sorted(temp_dict.items(), reverse=True)
            """
        except json.decoder.JSONDecodeError:
            self.processedptbl = None

    def getShodan(self):
        """
        Get Shodan data
        """
        if not self.shodanapi:
            return False

        # Lookup an IP
        # With history is crazy more data!!! up to 2.8MB per ip
        #self.shodandata = self.shodanapi.host(self.ip, history=True)

        try:
            self.shodandata = self.shodanobj.host(self.ip)
        except shodan.exception.APIError:
            #print(f'No shodan results for IP: {self.ip}')
            self.shodandata = None

    def getPT(self):
        """
        Get Passive total data
        """
        if not self.ptapi:
            return False
        command = "curl -m 25 --insecure -s -u " + self.ptuser + ":" + self.ptkey + " 'https://api.riskiq.net/pt/v2/dns/passive?query=" + self.ip + "'"
        temp = os.popen(command).read()
        try:
            self.processedptdata = json.loads(temp)
            self.processedptdata_results = None
            # Sort and reverse the keys
            # Store the samples in our dictionary so we can sort them
            temp_dict = {}
            try:
                for pt_results in self.processedptdata['results']:
                    temp_dict[pt_results['lastSeen']] = [pt_results['firstSeen'], pt_results['resolve'], pt_results['collected']]
                # Sort them by datetime and convert to list
                self.processedptdata_results = sorted(temp_dict.items(), reverse=True)
            except KeyError as e:
                print(f'Error in getPT: {e}')
                return False
        except json.decoder.JSONDecodeError:
            self.processedptdata = None

    def getExpert(self):
        """
        Get Expert data
        """
        command = f'grep ' + self.ip + ' ' + self.labelfile
        result = subprocess.run(command.split(), capture_output=True)
        try:
            ip, label, verolabel = result.stdout.decode("utf-8").replace('\n','').split(',')
        except ValueError:
            label = ''
        self.expertlabel = label

    def get_json(self):
        """
        Get a json version
        """
        data = {}
        data['ip'] = self.ip

        try:
            data['country'] = self.processedvtdata["country"]
        except KeyError:
            data['country'] = 'None'
        try:
            data['as'] = self.processedvtdata["as_owner"]
        except KeyError:
            data['as'] = 'None'
        try:
            data['rdns'] = self.processedvtdata["self.reversedns"]
        except KeyError:
            data['rdns'] = 'None'
        try:
            data['label'] = self.expertlabel
        except AttributeError:
            data['label'] = ''

        # geodata
        #{"status":"success","country":"Yemen","countryCode":"YE","region":"SA","regionName":"Amanat Alasimah","city":"Sanaa","zip":"","lat":15.3522,"lon":44.2095,"timezone":"Asia/Aden","isp":"Public Telecommunication Corporation","org":"YemenNet","as":"AS30873 Public Telecommunication Corporation","query":"134.35.218.63"}
        if self.geodata:
            data['geodata'] = self.geodata
        
        # vt resolutions. Is a list
        data['vt'] = {}
        try:
            if self.processedvtdata['resolutions'] != 'None':
                data['vt']['resolutions'] = []
                for count, resolution_tuple in enumerate(self.processedvtdata['resolutions']):
                    if count >= self.amount_to_print:
                        break
                    temp = {}
                    temp['date'] = resolution_tuple[0]
                    temp['domain'] = resolution_tuple[1]
                    data['vt']['resolutions'].append(temp)
        except KeyError:
            pass

        # vt urls. Is a list
        try:
            if self.processedvtdata['detected_urls'] != 'None':
                data['vt']['detected_urls'] = []
                for count, url_tuple in enumerate(self.processedvtdata['detected_urls']):
                    if count >= self.amount_to_print:
                        break
                    temp = {}
                    temp['date'] = url_tuple[0]
                    temp['url'] = url_tuple[1][0]
                    temp['detections'] = str(url_tuple[1][1]) + '/' + str(url_tuple[1][2])
                    data['vt']['detected_urls'].append(temp)
        except KeyError:
            pass


        # vt detected communicating samples. Is a list
        try:
            if self.processedvtdata['detected_communicating_samples'] != 'None':
                data['vt']['detected_communicating_samples'] = []
                for count, communcating_tuple in enumerate(self.processedvtdata['detected_communicating_samples']):
                    if count >= self.amount_to_print:
                        break
                    temp = {}
                    temp['date'] = communcating_tuple[0]
                    temp['detections'] = str(communcating_tuple[1][0]) + '/' + str(communcating_tuple[1][1])
                    temp['sha256'] = communcating_tuple[1][2]
                    data['vt']['detected_communicating_samples'].append(temp)
        except AttributeError:
            pass

        # vt detected downloaded samples. Is a list
        try:
            if self.processedvtdata['detected_downloaded_samples'] != 'None':
                data['vt']['detected_downloaded_samples'] = []
                for count, detected_tuple in enumerate(self.processedvtdata['detected_downloaded_samples']):
                    if count >= self.amount_to_print:
                        break
                    temp = {}
                    temp['date'] = detected_tuple[0]
                    temp['detections'] = str(detected_tuple[1][0]) + '/' + str(detected_tuple[1][1])
                    temp['sha256'] = detected_tuple[1][2]
                    data['vt']['detected_downloaded_samples'].append(temp)
        except AttributeError:
            pass

        # vt referrer downloaded samples. Is a list
        try:
            if self.processedvtdata['detected_referrer_samples'] != 'None':
                data['vt']['detected_referrer_samples'] = []
                for count, referrer_tuple in enumerate(self.processedvtdata['detected_referrer_samples']):
                    if count >= self.amount_to_print:
                        break
                    temp = {}
                    temp['sha256'] = referrer_tuple[0]
                    temp['detections'] = str(referrer_tuple[1][0]) + '/' + str(referrer_tuple[1][1])
                    data['vt']['detected_referrer_samples'].append(temp)
        except AttributeError:
            pass

        # pt data
        data['pt'] = {}
        if self.processedptdata:
            count = 0
            data['pt']['passive_dns'] = []
            for result in self.processedptdata_results:
                if count >= self.amount_to_print:
                    break
                temp = {}
                temp['lastseen'] = result[0]
                temp['firstseen'] = result[1][0]
                temp['hostname'] = result[1][1]
                data['pt']['passive_dns'].append(temp)
                count += 1

        # shodan data
        try:
            if self.shodandata:
                data['shodan'] = self.shodandata
        except AttributeError:
            pass

        data = json.dumps(data)
        return data

    def __repr__(self):
        """
        Print the object
        """
        pp = pprint.PrettyPrinter(width=60, compact=True)
        output = f'IP: {self.ip}. '
        try:
            emoji = ''
            if self.processedvtdata["country"] == 'US':
                emoji = "🇺🇸"
            output += f'Country: {self.processedvtdata["country"]} {emoji} . '
        except AttributeError:
            pass
        try:
            output += f'AS Org: {self.processedvtdata["as_owner"]}. '
        except AttributeError:
            pass
        try:
            output += f'RDNS: {self.reversedns}. '
        except AttributeError:
            pass
        try:
            output += f'Label: {self.expertlabel}. '
        except (KeyError, AttributeError):
            pass

        output += '\n'

        # Print geodata
        #{"status":"success","country":"Yemen","countryCode":"YE","region":"SA","regionName":"Amanat Alasimah","city":"Sanaa","zip":"","lat":15.3522,"lon":44.2095,"timezone":"Asia/Aden","isp":"Public Telecommunication Corporation","org":"YemenNet","as":"AS30873 Public Telecommunication Corporation","query":"134.35.218.63"}
        if self.geodata:
            output += f'GeoIP Data\n'
            try:
                country = self.geodata["country"]
            except KeyError:
                country = 'Unknown'
            try:
                countrycode = self.geodata["countryCode"]
            except KeyError:
                countrycode = 'Unknown'
            output += f'\tCountry: {country} ({countrycode})\n'
            try:
                regionname = self.geodata["regionName"]
            except KeyError:
                regionname = 'Unknown'
            try:
                region = self.geodata["region"]
            except KeyError:
                region = 'Unknown'
            output += f'\tRegionName: {regionname} {region}\n'
            output += f'\tCity: {self.geodata["city"]}\n'
            output += f'\tLat: {self.geodata["lat"]}\n'
            output += f'\tLon: {self.geodata["lon"]}\n'
            output += f'\tTZ: {self.geodata["timezone"]}\n'
            output += f'\tisp: {self.geodata["isp"]}\n'
            output += f'\tOrg: {self.geodata["org"]}\n'
            output += f'\tAS: {self.geodata["as"]}\n'
        
        # Print vt resolutions. Is a list
        try:
            if self.processedvtdata['resolutions'] != 'None':
                output += f'VT Resolutions (top {self.amount_to_print}, sorted by datetime):\n'
                for count, resolution_tuple in enumerate(self.processedvtdata['resolutions']):
                    if count >= self.amount_to_print:
                        break
                    output += f'\t{resolution_tuple[0]}: {resolution_tuple[1]}\n'
        except AttributeError:
            pass

        # Print vt urls. Is a list
        try:
            if self.processedvtdata['detected_urls'] != 'None':
                output += f'VT URLs (top {self.amount_to_print}, sorted by datetime):\n'
                for count, url_tuple in enumerate(self.processedvtdata['detected_urls']):
                    if count >= self.amount_to_print:
                        break
                    output += f'\t{url_tuple[0]}: {url_tuple[1][0]}. Positives: {url_tuple[1][1]}/{url_tuple[1][2]}\n'
        except AttributeError:
            pass

        # Print vt detected communicating samples. Is a list
        try:
            if self.processedvtdata['detected_communicating_samples'] != 'None':
                output += f'VT Detected Communicating Samples (top {self.amount_to_print}, sorted by datetime):\n'
                for count, communcating_tuple in enumerate(self.processedvtdata['detected_communicating_samples']):
                    if count >= self.amount_to_print:
                        break
                    output += f'\t{communcating_tuple[0]}: Positives: {communcating_tuple[1][0]}, Total: {communcating_tuple[1][1]}, SHA256: {communcating_tuple[1][2]}\n'
        except AttributeError:
            pass

        # Print vt detected downloaded samples. Is a list
        try:
            if self.processedvtdata['detected_downloaded_samples'] != 'None':
                output += f'VT Detected Downloaded Samples (top {self.amount_to_print}, sorted by datetime):\n'
                for count, detected_tuple in enumerate(self.processedvtdata['detected_downloaded_samples']):
                    if count >= self.amount_to_print:
                        break
                    output += f'\t{detected_tuple[0]}: Positives: {detected_tuple[1][0]}, Total: {detected_tuple[1][1]}, SHA256: {detected_tuple[1][2]}\n'
        except AttributeError:
            pass

        # Print vt referrer downloaded samples. Is a list
        try:
            if self.processedvtdata['detected_referrer_samples'] != 'None':
                output += f'VT Detected Referrer Samples (top {self.amount_to_print}, sorted by sha):\n'
                for count, referrer_tuple in enumerate(self.processedvtdata['detected_referrer_samples']):
                    if count >= self.amount_to_print:
                        break
                    output += f'\t{referrer_tuple[0]}: Positives: {referrer_tuple[1][0]}, Total: {referrer_tuple[1][1]}\n'
        except AttributeError:
            pass

        # Print pt data
        if self.processedptdata:
            try:
                count = 0
                output += f'PassiveTotal Data (top {self.amount_to_print}, sorted by lastSeen). '
                output += f'\tFirst Seen: {self.processedptdata["firstSeen"]}. Last Seen: {self.processedptdata["lastSeen"]}. Records: {self.processedptdata["totalRecords"]}\n'
                for result in self.processedptdata_results:
                    output += f'\tLastSeen: {result[0]}. FirstSeen: {result[1][0]}. Hostname: {result[1][1]}. \n'
                    if count >= self.amount_to_print:
                        break
                    count += 1
            except KeyError as e:
                print(f'Error {e}')

        # Pring shodan data
        if self.shodandata:
            output += f'Shodan Data. '
            output += f'\tTags: {self.shodandata["tags"]}\n'
            output += f'\tDomains: {self.shodandata["domains"]}\n'
            output += f'\tHostnames {self.shodandata["hostnames"]}\n'
            output += f'\tOrg {self.shodandata["org"]}\n'
            output += f'\tLast update {self.shodandata["last_update"]}\n'
            output += f'\tPorts {self.shodandata["ports"]}\n'
            #output += f'\tTimestamp {self.shodandata["data"]["timestamp"]}\n'
            #output += f'\t\tISP {self.shodandata["data"]["isp"]}\n'

        return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Stratosphere script to enrich an IP address with metadata.")
    parser.add_argument('-o', dest='output', help='Output a log file. Json', type=str, required=False)
    parser.add_argument('-v', dest='verbosity', help='Verbosity level.', default=1, required=False, type=int)
    parser.add_argument('-i', dest='ip', help='IP to enrich.', default=1, required=True, type=str)
    parser.add_argument('-m', dest='amount_to_print', help='How many lines to print per catetory max.', default=10, required=False, type=int)
    parser.add_argument('-e', dest='expert_labels', help='CSV file with the labels of the expert for each IP. Format IP,label', required=False, type=str)

    args = parser.parse_args()

    # Check if is a real ip or not
    ipaddress = args.ip
    ipobj = IP(ipaddress, args.amount_to_print, args.verbosity, labelfile=args.expert_labels)

    # Contact VT and get data
    if args.verbosity > 0:
        print('[+] Getting the VirusTotal data')
    ipobj.getVT()
    # Process VT data
    if args.verbosity > 0:
        print('[+] Processing the VirusTotal data')
    ipobj.processVT()
    # Get reverse DNS
    if args.verbosity > 0:
        print('[+] Getting the reverse DNS data')
    ipobj.getRDNS()
    # Get passivetotal
    if args.verbosity > 0:
        print('[+] Getting the PassiveTotal data')
    ipobj.getPT()
    # Get GeoLocation
    if args.verbosity > 0:
        print('[+] Getting the Geolocation data')
    ipobj.getGeo()
    # Get PassiveTotal blacklist
    #if args.verbosity > 0:
        #print('[+] Getting the PassiveTotal Blacklist')
    #ipobj.getPTBL()
    if args.verbosity > 0:
        print('[+] Getting the Shodan data')
    ipobj.getShodan()
    if args.expert_labels:
        if args.verbosity > 0:
            print('[+] Getting the Expert data')
        ipobj.getExpert()

    if args.output:
        with open(args.output, 'w+') as f:
            f.write(ipobj.get_json())
    else:
        print()
        print(ipobj)

