#!/usr/bin/python3
from DNS_alert_console import Console
import time
import smtplib
import datetime
import socket
import datetime
import requests
import json

# pip3 install dnsdist-console

console_ip = "127.0.0.1"
console_port = 5199
console_key = "="

max_querys_sec_allowed = 200       # The limit that a DNS query's may rise in the overview
check_top_x_domains    = 20        # Amount on domains monitored
dry_run                = False     # If True i will not add new rules
refresh_time           = 3         # How ofter should i check if a domain has a high rise
activate_on_backend_req= 2000      # Don't take action if backend servers did less than x amount of requests
command                = """addAction("%domain_name%", QPSAction(100))"""
command_small_len      = """addAction(QNameRule('%domain_name%'),QPSAction(100))"""     # This is not a wildcard. It will only match this specific domain. So .nl. and not true.nl.


abnormal_limit = {"in-addr.arpa.":400, "trueserver.nl.": 200, "Rest":99999999}
hostname = socket.gethostname()
hostname = hostname+".true.nl"
print("Hostname: ",hostname)
status_pages = {"ns1.true.nl":"http://blabla:8083/",
                "ns2.true.nl":"http://miaw:8083/",
                "ns3.true.nl":"http://behhhh:8083"}

teams_webhook_url = "https://zzzzzz.webhook.office.com/webhookb2/"
status_page = status_pages[hostname]
previous_statisics = {}
previous_nr_requests = 99999999999999999999999

already_notified = {}
already_notified_count = {}
def get_nr_backend_requests():
    try:
        console = Console(host=console_ip,
                          port=console_port,
                          key=console_key)
        o = console.send_command(cmd="dumpStats()")
        output = o.splitlines()
        for line in output:
            if "responses              " in line:
                return int(line.split("\t")[2])
        console.disconnect()
        # print(o)
    except:
        print("FAILED TO GET BACKEND REQUESTS!!")
        return 0

def get_topQueries(nr):
    try:
        console = Console(host=console_ip,
                          port=console_port,
                          key=console_key)
        o = console.send_command(cmd="topQueries("+nr+",2)")
        output = o.splitlines()
        #print(o)
        domain_statisics = {}
        for line in output:
            # Removing double spaces
            tmp = ' '.join(line.split())
            # Split the different columns
            columns = tmp.split(" ")
            domain_statisics[columns[1]] = {"id":int(columns[0]),"domain_name":columns[1],"hits":int(columns[2]),"percantage":columns[3]}
        console.disconnect()
        # print(domain_statisics)
        return domain_statisics
    except:
        print("FAILED TO GET TOP QUERIES!!")
        domain_statisics = {}
        return domain_statisics



def send_teams(domain, state, hostname,hits_this_second):

    if (domain in already_notified and already_notified[domain] > (datetime.datetime.now() - datetime.timedelta(minutes=15))) or (domain in already_notified_count and already_notified_count[domain] > hits_this_second):

        print("already notified")
        return
    
    already_notified[domain]        = datetime.datetime.now()
    already_notified_count[domain]  = hits_this_second
    if dry_run:
        intro_text = "DNS Received high amount of query's (IN DRY RUN, NO AUTOMATED ACTION TAKEN)"
    else:
        intro_text = "DNS Ratelimit installed for domain: "

    if state == "ACK":
        attachment_color = "43C6FF"
    elif state in ["CRITICAL", "DOWN", "UNREACHABLE"]:
        attachment_color = "FF0000"
    elif state in ["WARNING", "UNKNOWN"]:
        attachment_color = "FF8300"
    elif state in ["OK", "UP"]:
        attachment_color = "19CD00"
    else:
        attachment_color = "43C6FF"

    output = None
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "{}".format(attachment_color),
        "summary": "DNS Ratelimiting",
        "sections": [{
            "activityTitle": "{}".format(intro_text + domain + " Received "+str(int(hits_this_second))+ "query/s. On "+hostname+ " More info on: https://wiki.true.nl/Web:Nameservers"),
            "facts": []
        }]
    }

    if state in ["CRITICAL", "DOWN", "UNREACHABLE", "WARNING", "UNKNOWN"]:
        payload["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "DNS Dist status pagina",
                "targets": [{ "os": "default", "uri": status_page}]
            }
        ]

    r = requests.post(teams_webhook_url, json.dumps(payload))

    if r.status_code != 200:
        print("ERROR: Got HTTP {} from Teams, response body: {}".format(r.status_code, r.text))

while True:
    f = open("/var/log/dns_flood.log", "a+")
    domain_statisics          = get_topQueries(str(check_top_x_domains))
    nr_backend_requests       = get_nr_backend_requests()
    increased_nr_requests     = nr_backend_requests - previous_nr_requests
    increased_nr_requests_sec = int(increased_nr_requests / refresh_time)
    #print(increased_nr_requests_sec)
    if increased_nr_requests_sec > activate_on_backend_req:
        for domain in domain_statisics:
            try:
                hits_this_second = (int(domain_statisics[domain]["hits"]) - int(previous_statisics[domain]["hits"])) / refresh_time
                if domain in abnormal_limit:
                    if hits_this_second >= abnormal_limit[domain]:
                        execute_command = command.replace('%domain_name%', domain_statisics[domain]["domain_name"])
                    else:
                        continue
                else:
                    if hits_this_second >= max_querys_sec_allowed:
                        if len(domain) < 6: # This is for "." .nl .com
                            execute_command = command_small_len.replace('%domain_name%', domain_statisics[domain]["domain_name"])
                        else:
                            execute_command = command.replace('%domain_name%', domain_statisics[domain]["domain_name"])
                    else:
                        continue

                f.write(str(datetime.datetime.now()) + "\t" + str(int(hits_this_second)) + "/s on " + domain + "\n")
                print(  str(datetime.datetime.now()) + "\t" + str(int(hits_this_second)) + "/s on " + domain)
                send_teams(domain, "WARNING", hostname,hits_this_second)
                if dry_run != True:
                    console = Console(host=console_ip,
                                      port=console_port,
                                      key=console_key)
                    console.send_command(cmd=execute_command)
                    console.disconnect()

            except KeyError:
                #print(domain+" Was privously unknown")
                pass


    previous_nr_requests = nr_backend_requests
    previous_statisics = domain_statisics.copy()
    f.close()
    time.sleep(refresh_time)

