import requests
import json
import argparse
from tabulate import tabulate
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from zoomeye.sdk import *
from shodan import *


def censysio(address):
    ID = ""                                 #provide Censys.io API ID
    SECRET = ""                                 #provide Censys.io API Secret
    page = 1
    data = []
    print('\n')
    print("Searching on Censys.io.......")
    print('\n')
    try:
        while page != 0:
            r = requests.post("https://censys.io/api/v1/search/ipv4", auth=(ID, SECRET), json={"query": address})
            json_data = r.json()
            pages = json_data['metadata']['pages']
            for result in json_data['results']:
                ip = result['ip']
                protocol = result['protocols']
                protocol = [p.split("/")[0] for p in protocol]
                protocol.sort(key=float)
                protocolList = ','.join(map(str, protocol))
                location = result['location.country']
                newList = [ip, protocolList, location]

                data.append(newList)
            print(tabulate(data, headers=["IP", "PORTS", "LOCATION"]))
            if page == pages:
                page = 0
            elif page < pages:
                page = page + 1
            elif page > pages:
                page = 0
    except:
        print("Error with Censys.io API ID and SECRET. Please provide proper credentials.")
    print('\n')



def dnsDump(address):
    data = []
    print('\n')
    print("Searching on DNSDumpster.......")
    print('\n')
    res = DNSDumpsterAPI().search(address)
    listH = res['dns_records']['host']
    for host in listH:
        domain = host['domain']
        ip = host['ip']
        reverse = host['reverse_dns']
        country = host['country']
        header = host['header']
        newList = [domain, ip, reverse, country, header]
        data.append(newList)

    print(tabulate(data, headers=["Domanin", "IP", "REVERSE", "LOCATION", "TECHNOLOGY"]))
    print('\n')


def zoomEye(address):
    try:
        zm = ZoomEye()
        zm.api_key=''                       #provide ZoomEye API Key

        data = zm.dork_search(address)


        ip=zm.dork_filter("ip,port,country")
        print('\n')
        print('Searching on ZoomEye.......')
        print('\n')
        print(tabulate(ip, headers=["IP", "PORT", "LOCATION"]))
        print('\n')
    except:
        print("Error with zoomeye credentials")

def shod(address):
    try:
        data = []
        print('\n')
        print("Searching on Shodan.......")
        print('\n')
        api = Shodan('')                        #provide Shodan API Key
        ipinfo = api.search(address)

        for host in ipinfo['matches']:
            ip = host['ip_str']
            port = host['port']
            org = host['org']
            location = host['location']['country_name']
            newList = [ip, port, org, location]
            data.append(newList)
        print(tabulate(data, headers=["IP", "PORT", "ORGANIZATION", "LOCATION"]))
        print('\n')

    except:
        print("Error with Shodan Api")



def securityTrails(address):
    try:
        print('\n')
        print('Searching on SecurityTrails.......')
        print('\n')
        url1 = "https://api.securitytrails.com/v1/domain/" + address
        url2 = "https://api.securitytrails.com/v1/domain/"+address+"/subdomains"
        url3 = "https://api.securitytrails.com/v1/history/"+address+"/dns/a"

        querystring = {"children_only":"false","include_inactive":"true"}

        headers = {"Accept": "application/json", "APIKEY" : ""}                 #provide SecurityTrails Api Key
        response1 = requests.request("GET", url1, headers=headers)
        response2 = requests.request("GET", url2, headers=headers, params=querystring)
        response3 = requests.request("GET", url3, headers=headers)
       # print(response1.json())
        nsList = []
        aRecList = []
        subList = []


        for details in response1.json()['current_dns']['ns']['values']:
            nameserver = details['nameserver']
            organization = details['nameserver_organization']
            newList = [nameserver, organization]
            nsList.append(newList)
        print(tabulate(nsList, headers=["NameServer", "ORGANIZATION"]))
        print('\n')

        for details in response1.json()['current_dns']['a']['values']:
            ip = details['ip']
            organization = details['ip_organization']
            newList = [ip, organization]
            aRecList.append(newList)
        print("Current DNS Record")
        print(tabulate(aRecList, headers=["IP", "ORGANIZATION"]))
        print('\n')

        for host in response2.json()['subdomains']:
            subdomain = host+"."+address
            newList=[subdomain]
            subList.append(newList)
        print(tabulate(subList, headers=["SUBDOMAINS"]))
        print('\n')

        response3 = requests.request("GET", url3, headers=headers)
        aHList =[]
        ipList = []
        for records in response3.json()['records']:
            ipList = []
            for list in records['values']:
                ipList.append(list['ip'])
            lSeen = records['last_seen']
            fSeen = records['first_seen']
            organi = ""
            for org in records['organizations']:
                organi = org
            for i in ipList:
                ip = i
                newList = [ip , fSeen, lSeen, organi]
                aHList.append(newList)
        print("Historic DNS Record")
        print(tabulate(aHList, headers=["IP", "FIRST SEEN", "LAST SEEN", "ORGANIZATION"]))
        print('\n')

    except:
        print("Error with Security Trails API KEY")


def reverseIP(address):
    url = "https://domains.yougetsignal.com/domains.php"
    query = {'remoteAddress': address}
    response = requests.post(url, data=query)
    reverseList=[]
    print('\n')
    print('Performing Reverse IP LookUP......')
    print('\n')
    if response.json()['status'] == 'Fail':
        print(response.json()['message'])
    else:
        count = 0
        total = response.json()['domainCount']
        t = int(total)
        if t > 0:
            for details in response.json()['domainArray']:
                count = count + 1
                newList = [count, details[0]]
                reverseList.append(newList)
            ip = response.json()['remoteIpAddress']
            print("IP address of the server: " + ip)
            print(tabulate(reverseList, headers=["Sr#", "HOSTED DOMAINS ON SAME SERVER"]))
            print('\n')
        else:
            print("No other domain discovered")



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help="Provide the url that you want to scan")
    parser.add_argument('-a' , '--all', action='store_true' ,help='Search on all resources')
    parser.add_argument('-sT', '--securityTrails', action='store_true', help='Search on SecurityTrails')
    parser.add_argument('-s', '--shodan', action='store_true', help='Search on Shodan')
    parser.add_argument('-d', '--dnsdumpster', action='store_true', help='Search on DnsDumpster')
    parser.add_argument('-c', '--censys', action='store_true', help='Search on Censys.io')
    parser.add_argument('-z', '--zoomeye', action='store_true', help='Search on ZoomEye')
    parser.add_argument('-r', '--reverse', action='store_true', help='Perform reverse ip look up')
    args = parser.parse_args()

    if args.securityTrails or args.shodan or args.dnsdumpster or args.censys or args.reverse or args.zoomeye:

        if args.securityTrails:
            securityTrails(args.url)
        if args.shodan:
            shod(args.url)
        if args.dnsdumpster:
            dnsDump(args.url)
        if args.censys:
            censysio(args.url)
        if args.zoomeye:
            zoomEye(args.url)
        if args.reverse:
            reverseIP(args.url)

    elif args.all:
        securityTrails(args.url)
        shod(args.url)
        zoomEye(args.url)
        censysio(args.url)
        reverseIP(args.url)
        dnsDump(args.url)

    else:
        print("Kindly provide proper arguements. Example:   python3 shadow.py -u example.com -a")




print("   _____ _    _          _____   ______          __   __          __     _      _  __ ")
print("  / ____| |  | |   /\   |  __ \ / __ \ \        / /   \ \        / /\   | |    | |/ / ")
print(" | (___ | |__| |  /  \  | |  | | |  | \ \  /\  / /     \ \  /\  / /  \  | |    | ' /  ")
print("  \___ \|  __  | / /\ \ | |  | | |  | |\ \/  \/ /       \ \/  \/ / /\ \ | |    |  <   ")
print("  ____) | |  | |/ ____ \| |__| | |__| | \  /\  /         \  /\  / ____ \| |____| . \  ")
print(" |_____/|_|  |_/_/    \_\_____/ \____/   \/  \/           \/  \/_/    \_\______|_|\_\ ")
print("                                                                                      ")                             




print("Assets scanning tool")
print("created by: Sherdil Gilani")
print('\n')
print("Usage: python3 shadow.py -u example.com -a")

main()
