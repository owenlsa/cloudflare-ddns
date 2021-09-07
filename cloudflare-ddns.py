import requests
import json
import sys
import signal
import os
import time
import threading
import re
import socket
import platform


class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print("Stopping main thread...")
        self.kill_now.set()


def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    for option in config["cloudflare"]:
        answer = cf_api(
            "zones/" + option['zone_id'] +
            "/dns_records?per_page=100&type=" + type,
            "GET", option)
    if answer is None or answer["result"] is None:
        time.sleep(5)
        return
    for record in answer["result"]:
        identifier = str(record["id"])
        cf_api(
            "zones/" + option['zone_id'] + "/dns_records/" + identifier,
            "DELETE", option)
        print("Deleted stale record " + identifier)


def checkValidIP(ip, type):
    try:
        if type == "ipv4":
            socket.inet_pton(socket.AF_INET, ip)
        elif type == "ipv6":
            socket.inet_pton(socket.AF_INET6, ip)
        else:
            raise ValueError("IP type error, must be 'ipv4' or 'ipv6'")
        return True
    except socket.error:
        return False


def getIPs(use_local_ip, ipv4_enabled, ipv6_enabled):
    if use_local_ip:
        return getLocalIPs(ipv4_enabled, ipv6_enabled)
    else:
        return getPublicIPs(ipv4_enabled, ipv6_enabled)


def getLocalIPs(ipv4_enabled, ipv6_enabled):
    # get local IPs
    if platform.system() == "Linux":
        p = os.popen("hostname -I")
        ip_list = str(p.read()).strip().split(' ')
    elif platform.system() == "Windows":
        assert socket.gethostname()
        nets = socket.getaddrinfo(socket.gethostname(), None)
        assert nets
        ip_list = []
        for net in nets:
            ip_list.append(net[-1][0])
    else:
        raise ValueError("os type error, check result of platform.system()")

    ips = {}
    forbid_prefix = ["127.", "172.", "192.", "fe80:"]
    for ip in ip_list:
        if any(list(prefix in ip for prefix in forbid_prefix)):
            continue
        if ipv4_enabled and checkValidIP(ip, type="ipv4"):
            ips["ipv4"] = {
                "type": "A",
                "ip": ip
            }
        if ipv6_enabled and checkValidIP(ip, type="ipv6"):
            ips["ipv6"] = {
                "type": "AAAA",
                "ip": ip
            }
    return ips


def getPublicIPs(ipv4_enabled, ipv6_enabled):
    # get public IPs
    a = None
    aaaa = None
    if ipv4_enabled:
        try:
            a = requests.get("https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception:
            deleteEntries("A")
    if ipv6_enabled:
        try:
            aaaa = requests.get(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            deleteEntries("AAAA")
    ips = {}
    if(a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if(aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips


def commitRecord(ip):
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        ttl = 0  # default Cloudflare TTL, 0 for auto
        for subdomain_type in subdomains.keys():
            if subdomain_type != ip["type"]:
                continue
            subdomain = subdomains[subdomain_type]
            subdomain = subdomain.lower().strip()
            record = {
                "type": subdomain_type,
                "name": subdomain,
                "content": ip["ip"],
                "proxied": option["proxied"],
                "ttl": ttl
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] +
                "/dns_records?per_page=100&type=" + ip["type"],
                "GET", option)
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied']:
                                modified = True
            if identifier:
                if modified:
                    print("Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
                else:
                    print("Record unchanged " + str(record))
            else:
                print("Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            # for identifier in duplicate_ids:
            #    identifier = str(identifier)
            #    print("🗑️ Deleting stale record " + identifier)
            #    response = cf_api(
            #        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
            #        "DELETE", option)
    return True


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint,
            headers=headers, json=data)

    if response.ok:
        return response.json()
    else:
        print("Error sending '" + method +
              "' request to '" + response.url + "':")
        print(response.text)
        return None


def updateIPs(ips):
    assert len(ips) == 2, "Error getting IPs, len(IPs)=" + str(len(ips))
    for ip in ips.values():
        commitRecord(ip)


if __name__ == '__main__':
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    # print("chdir to", sys.path[0])
    os.chdir(sys.path[0])
    # check python version
    version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))
    if(version < 3.5):
        raise Exception("This script requires Python 3.5+")

    # get config.json
    PATH = os.getcwd() + "/"
    try:
        with open(PATH + "config.json") as config_file:
            config = json.loads(config_file.read())
    except:
        raise Exception("Error reading config.json")

    if config:
        try:
            ipv4_enabled = config["ipv4"]
            ipv6_enabled = config["ipv6"]
            use_local_ip = config["local_ip"]
        except:
            raise Exception("Please enable ipv4 or ipv6 at least one")
        if(len(sys.argv) > 1):
            if(sys.argv[1] == "--repeat" and len(sys.argv) > 2):
                delay = int(sys.argv[2]) * 60
                if ipv4_enabled and ipv6_enabled:
                    print("Updating IPv4 (A) & IPv6 (AAAA) records every 5 minutes")
                elif ipv4_enabled and not ipv6_enabled:
                    print("Updating IPv4 (A) records every 5 minutes")
                elif ipv6_enabled and not ipv4_enabled:
                    print("Updating IPv6 (AAAA) records every 5 minutes")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    if killer.kill_now.wait(delay):
                        break
                    updateIPs(getIPs(use_local_ip, ipv4_enabled, ipv6_enabled))
            else:
                print("Error param! e.g. --repeat 5, for updating every 5 minutes")
        else:
            updateIPs(getIPs(use_local_ip, ipv4_enabled, ipv6_enabled))
