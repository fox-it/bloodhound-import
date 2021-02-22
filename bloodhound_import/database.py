"""
Code borrowed from
https://github.com/fox-it/aclpwn.py/blob/master/aclpwn/database.py
"""
from neo4j import GraphDatabase
import platform
import json
import os


def init_driver(ip, port, scheme, user, password):
    uri = "{}://{}:{}".format(scheme, ip, port)
    driver = GraphDatabase.driver(uri, auth=(user, password))
    return driver


def detect_db_config():
    """
    Detect bloodhound config, which is stored in appData.
    OS dependent according to https://electronjs.org/docs/api/app#appgetpathname
    """
    system = platform.system()
    if system == 'Windows':
        try:
            directory = os.environ['APPDATA']
        except KeyError:
            return (None, None)
        config = os.path.join(directory, 'BloodHound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    if system == 'Linux':
        try:
            directory = os.environ['XDG_CONFIG_HOME']
        except KeyError:
            try:
                directory = os.path.join(os.environ['HOME'], '.config')
            except KeyError:
                return (None, None)
        config = os.path.join(directory, 'bloodhound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    if system == 'Darwin':
        try:
            directory = os.path.join(os.environ['HOME'], 'Library', 'Application Support')
        except KeyError:
            return (None, None)
        config = os.path.join(directory, 'bloodhound', 'config.json')
        try:
            with open(config, 'r') as configfile:
                configdata = json.load(configfile)
        except IOError:
            return (None, None)

    # If we are still here, we apparently found the config :)
    try:
        username = configdata['databaseInfo']['user']
    except KeyError:
        username = 'neo4j'
    try:
        password = configdata['databaseInfo']['password']
    except KeyError:
        password = None
    return username, password
