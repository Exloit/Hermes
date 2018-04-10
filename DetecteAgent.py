# /usr/bin/env python3
# -*- coding: utf-8 -*-  
# detecte and remove the agent

import empireapi
from termcolor import colored
import time

if __name__ == '__main__':
    token = {'token': None}
    agents = {}
    agents_second = {}
    token['token'] = empireapi.login("admin","123456")
    while True:
        for agent in empireapi.get_agents(token)['agents']:
            agent_name = agent['name']
            if empireapi.agent_finished_initializing(agent):
                empireapi.print_good(colored('Agent Detail'.format(agent['name']), 'yellow') + ' => Name: {} lastseen_time: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['name'],
                                                                                                                                                           agent['lastseen_time'],
                                                                                                                                                           agent['hostname'],
                                                                                                                                                           agent['username'],
                                                                                                                                                           agent['high_integrity']))
                agents[agent_name] = {'id': agent['ID'],
                                      'lastseen_time': agent['lastseen_time'],
                                      'hostname': agent['hostname'],
                                      'username': agent['username'],
                                      'high_integrity': agent['high_integrity'],
                                      'os': agent['os_details']}
        time.sleep(20)
        for agent in empireapi.get_agents(token)['agents']:
            agent_name = agent['name']
            if empireapi.agent_finished_initializing(agent):
                empireapi.print_good(colored(' Agent Detail '.format(agent['name']), 'yellow') + ' => Name: {} lastseen_time: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['name'],
                                                                                                                                                           agent['lastseen_time'],
                                                                                                                                                           agent['hostname'],
                                                                                                                                                           agent['username'],
                                                                                                                                                           agent['high_integrity']))
                print('\n')
                agents_second[agent_name] = {'id': agent['ID'],
                                      'lastseen_time': agent['lastseen_time'],
                                      'hostname': agent['hostname'],
                                      'username': agent['username'],
                                      'high_integrity': agent['high_integrity'],
                                      'os': agent['os_details']}
                                      
        for agent_name in agents.keys():
            if agent_name in agents_second.keys():
                if agents[agent_name]['lastseen_time'] == agents_second[agent_name]['lastseen_time'] :
                    print(empireapi.remove_agent(agent_name, token))
                    agents_second.pop(agent_name)
                    #empireapi.remove_agent(agent_name, token)
                    print("{} is death , I have remove it".format(agent_name))
                    time.sleep(2)