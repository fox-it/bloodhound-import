"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

from bloodhound_import import database
from dataclasses import dataclass
import codecs
import ijson
import logging
import neo4j
import sys
import os
import re
import json
from clint.textui import progress
import queue, threading, time

running=True
q = queue.Queue()
total = 0
count = 0

@dataclass
class Query:
    query: str
    properties: dict


SYNC_COUNT = 100

def check_object(tx: neo4j.Transaction, source_label: str, type: str = "objectid", **kwargs) -> bool:
    query = 'UNWIND $props AS prop MATCH (n:{1} {{{0}: prop.source}}) RETURN n.{0} as {0}'
    query = query.format(type, source_label)
    result = [r for r in tx.run(query, **kwargs)]
    return len(result) > 0

def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str, type: str = "objectid") -> str:
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) ON MATCH SET n:{1} ON CREATE SET n:{1} MERGE (m:Base {{objectid: prop.target}}) ON MATCH SET m:{2} ON CREATE SET m:{2} MERGE (n)-[r:{3} {4}]->(m)'
    return insert_query.format(type, source_label, target_label, edge_type, edge_props)

def check_add_edge(tx: neo4j.Transaction, source_label: str, target_label: str, edge_type: str, edge_props: str, type: str = "objectid", **kwargs) -> list:
    
    source = kwargs.get('props', {}).get('source', None)
    target = kwargs.get('props', {}).get('target', None)

    if source is None:
        raise Exception("Source is None")

    if target is None:
        raise Exception("Target is None")

    query = 'UNWIND $props AS prop MATCH (n:{1} {{{0}: prop.source}}) MATCH (m:{2} {{objectid: prop.target}}) MATCH (n)-[r:{3} {4}]->(m) RETURN n.{0} as source'
    query = query.format(type, source_label, target_label, edge_type, edge_props)

    result = [
            r for r in tx.run(query, **kwargs)
            if r['source'] == source
        ]

    if len(result) > 0:
        return []

    return [
            dict(
                query=build_add_edge_query(source_label, target_label, edge_type, edge_props, type),
                data=kwargs
                )
        ]


def process_ace_list(ace_list: list, objectid: str, objecttype: str, tx: neo4j.Transaction) -> list:
    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']

        if objectid == principal:
            continue

        props = dict(
            source=principal,
            target=objectid,
            isinherited=entry['IsInherited'],
        )
        
        yield from check_add_edge(tx, 
                    principaltype, objecttype, right, '{isacl: true, isinherited: prop.isinherited}',
                    props=props
                )

def process_spntarget_list(spntarget_list: list, objectid: str, tx: neo4j.Transaction) -> None:
    for entry in spntarget_list:
        query = build_add_edge_query('User', 'Computer', '', '{isacl: false, port: prop.port}')
        props = dict(
            source=objectid,
            target=entry['ComputerSID'],
            port=entry['Port'],
        )
        yield from check_add_edge(tx, 
                    'User', 'Computer', '', '{isacl: false, port: prop.port}',
                    props=props
                )

def add_constraints(tx: neo4j.Transaction):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction.
    """
    tx.run('CREATE CONSTRAINT base_objectid_unique ON (b:Base) ASSERT b.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT computer_objectid_unique ON (c:Computer) ASSERT c.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT domain_objectid_unique ON (d:Domain) ASSERT d.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT group_objectid_unique ON (g:Group) ASSERT g.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT user_objectid_unique ON (u:User) ASSERT u.objectid IS UNIQUE')
    tx.run("CREATE CONSTRAINT ON (c:User) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


def parse_ou(tx: neo4j.Transaction, ou: dict) -> list:
    """Parses a single ou.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    trans = []
    identifier = ou['ObjectIdentifier'].upper()
    props = {'map': ou['Properties'], 'source': identifier}

    if not check_object(tx, 'OU', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:OU ON CREATE SET n:OU SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]


    if 'Aces' in ou and ou['Aces'] is not None:
        trans += [ t for t in process_ace_list(ou['Aces'], identifier, "OU", tx) ]

    options = [
        ('Users', 'User', 'Contains'),
        ('Computers', 'Computer', 'Contains'),
        ('ChildOus', 'OU', 'Contains'),
    ]

    for option, member_type, edge_name in options:
        if option in ou and ou[option]:
            targets = ou[option]
            for target in targets:
                trans += check_add_edge(tx, 
                    'OU', member_type, edge_name, '{isacl: false}',
                    props=dict(source=identifier, target=target)
                )

    if 'Links' in ou and ou['Links']:
        for gpo in ou['Links']:
            trans += check_add_edge(tx, 
                    'GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}',
                    props=dict(source=identifier, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced'])
                )

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    for option, edge_name in options:
        if option in ou and ou[option]:
            targets = ou[option]
            for target in targets:
                for computer in ou['Computers']:
                    trans += check_add_edge(tx, 
                        target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}',
                        props=dict(target=computer, source=target['ObjectIdentifier'])
                    )

    return trans


def parse_gpo(tx: neo4j.Transaction, gpo: dict) -> list:
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction
        gpo {dict} -- Single gpo object.
    """
    trans = []
    identifier = gpo['ObjectIdentifier']
    props = {'map': gpo['Properties'], 'source': identifier}

    if not check_object(tx, 'GPO', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:GPO ON CREATE SET n:GPO SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]


    if "Aces" in gpo and gpo["Aces"] is not None:
        trans += [ t for t in process_ace_list(gpo['Aces'], identifier, "GPO", tx) ]

    return trans


def parse_user(tx: neo4j.Transaction, user: dict) -> list:
    """Parse a user object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    trans = []
    identifier = user['ObjectIdentifier']
    props = {'map': user['Properties'], 'source': identifier}

    if not check_object(tx, 'User', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:User ON CREATE SET n:User SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]


    if 'PrimaryGroupSid' in user and user['PrimaryGroupSid']:
        trans += check_add_edge(tx, 
                'User', 'Group', 'MemberOf', '{isacl: false}',
                props=dict(source=identifier, target=user['PrimaryGroupSid'])
            )

    if 'AllowedToDelegate' in user and user['AllowedToDelegate']:
        for entry in user['AllowedToDelegate']:
            trans += check_add_edge(tx, 
                'User', 'Computer', 'AllowedToDelegate', '{isacl: false}',
                props=dict(source=identifier, target=entry)
            )

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        trans += [ t for t in process_ace_list(user['Aces'], identifier, "User", tx) ]

    if 'SPNTargets' in user and user['SPNTargets'] is not None:
        trans += [ t for t in process_spntarget_list(user['SPNTargets'], identifier, tx) ]

    return trans

def parse_group(tx: neo4j.Transaction, group: dict) -> list:
    """Parse a group object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        group {dict} -- Single group object from the bloodhound json.
    """
    trans = []
    properties = group['Properties']
    identifier = group['ObjectIdentifier']
    members = group['Members']
    props = {'map': properties, 'source': identifier}

    if not check_object(tx, 'Group', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Group ON CREATE SET n:Group SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]


    if 'Aces' in group and group['Aces'] is not None:
        trans += [ t for t in process_ace_list(group['Aces'], identifier, "Group", tx) ]

    for member in members:
        trans += check_add_edge(tx, 
                member['ObjectType'], 'Group', 'MemberOf', '{isacl: false}',
                props=dict(source=member['ObjectIdentifier'], target=identifier)
            )

    return trans

def parse_domain(tx: neo4j.Transaction, domain: dict) -> list:
    """Parse a domain object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        domain {dict} -- Single domain object from the bloodhound json.
    """
    trans = []
    identifier = domain['ObjectIdentifier']
    props = {'map': domain['Properties'], 'source': identifier}
    
    if not check_object(tx, 'Domain', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Domain ON CREATE SET n:Domain SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]

    if 'Aces' in domain and domain['Aces'] is not None:
        trans += [ t for t in process_ace_list(domain['Aces'], identifier, "Domain", tx) ]

    trust_map = {0: 'ParentChild', 1: 'CrossLink', 2: 'Forest', 3: 'External', 4: 'Unknown'}
    if 'Trusts' in domain and domain['Trusts'] is not None:
        for trust in domain['Trusts']:
            trust_type = trust['TrustType']
            direction = trust['TrustDirection']
            props = {}
            if direction in [1, 3]:
                props = dict(
                    source=identifier,
                    target=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            elif direction in [2, 4]:
                props = dict(
                    target=identifier,
                    source=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            else:
                logging.error("Could not determine direction of trust... direction: %s", direction)
                continue
            
            trans += check_add_edge(tx, 
                'Domain', 'Domain', 'TrustedBy', '{sidfiltering: prop.sidfiltering, trusttype: prop.trusttype, transitive: prop.transitive, isacl: false}',
                props=props
            )


    options = [
        ('Users', 'User', 'Contains'),
        ('Computers', 'Computer', 'Contains'),
        ('ChildOus', 'OU', 'Contains'),
    ]

    for option, member_type, edge_name in options:
        if option in domain and domain[option]:
            targets = domain[option]
            for target in targets:
                trans += check_add_edge(tx, 
                    'OU', member_type, edge_name, '{isacl: false}',
                    props=dict(source=identifier, target=target)
                )

    if 'Links' in domain and domain['Links']:
        for gpo in domain['Links']:
            trans += check_add_edge(tx, 
                    'GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}',
                    props=dict(source=identifier, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced'])
                )

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    for option, edge_name in options:
        if option in domain and domain[option]:
            targets = domain[option]
            for target in targets:
                for computer in domain['Computers']:
                    trans += check_add_edge(tx, 
                        target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}',
                        props=dict(target=computer, source=target['ObjectIdentifier'])
                    )

    return trans

def parse_computer(tx: neo4j.Transaction, computer: dict) -> list:
    """Parse a computer object.

    Arguments:
        session {neo4j.Transaction} -- Neo4j transaction
        computer {dict} -- Single computer object.
    """
    trans = []
    identifier = computer['ObjectIdentifier']
    props = {'map': computer['Properties'], 'source': identifier}

    if not check_object(tx, 'Computer', props=props):
        trans += [
            dict(
                query='UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Computer ON CREATE SET n:Computer SET n += prop.map',
                data=dict(
                    props=props
                    )
                )
            ]

    if 'PrimaryGroupSid' in computer and computer['PrimaryGroupSid']:
        trans += check_add_edge(tx, 
            'Computer', 'Group', 'MemberOf', '{isacl:false}',
            props=dict(source=identifier, target=computer['PrimaryGroupSid'])
            )

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        for entry in computer['AllowedToDelegate']:
            trans += check_add_edge(tx, 
                'Computer', 'Group', 'MemberOf', '{isacl:false}',
                props=dict(source=identifier, target=entry)
            )

    
    # (Property name, Edge name, Use "Results" format)
    options = [
        ('LocalAdmins', 'AdminTo', True),
        ('RemoteDesktopUsers', 'CanRDP', True),
        ('DcomUsers', 'ExecuteDCOM', True),
        ('PSRemoteUsers', 'CanPSRemote', True),
        ('AllowedToAct', 'AllowedToAct', False),
        ('AllowedToDelegate', 'AllowedToDelegate', False),
    ]

    for option, edge_name, use_results in options:
        if option in computer:
            targets = computer[option]['Results'] if use_results else computer[option]
            for target in targets:
                if isinstance(target, str):
                    trans += check_add_edge(tx, 
                        'Base', 'Computer', edge_name, '{isacl:false, fromgpo: false}', "name",
                        props=dict(source=target, target=identifier)
                    )

                else:
                    trans += check_add_edge(tx, 
                        target['ObjectType'], 'Computer', edge_name, '{isacl:false, fromgpo: false}',
                        props=dict(source=target['ObjectIdentifier'], target=identifier)
                    )

    # (Session type, source)
    session_types = [
        ('Sessions', 'netsessionenum'),
        ('PrivilegedSessions', 'netwkstauserenum'),
        ('RegistrySessions', 'registry'),
    ]

    for session_type, source in session_types:
        if session_type in computer and computer[session_type]['Results']:
            for entry in computer[session_type]['Results']:
               trans += check_add_edge(tx, 
                    'Computer', 'User', 'HasSession', '{isacl:false, source:"%s"}' % source,
                    props=dict(source=entry['UserId'], target=identifier)
                )

    if 'Aces' in computer and computer['Aces'] is not None:
        trans += [ t for t in process_ace_list(computer['Aces'], identifier, "Computer", tx) ]
    
    return trans

def executer(tx: neo4j.Transaction, transactions: list):
    for t in transactions:
        data = t['data']
        if not isinstance(data, dict):
            logging.error("Invalid data: %s", data)
            continue
        tx.run(t['query'], **data)

def worker(index, parse_function, **kwargs):
    global running, count
    icount = 0
    driver = database.init_driver(**kwargs)
    while running and icount < 100:
        entry = q.get()
        try:
            do_task(entry, parse_function, driver)
        
        except neo4j.exceptions.TransientError as e:
            # Deadlock, try to reopen a new connection
            driver.close()
            time.sleep(0.500)
            driver = database.init_driver(**kwargs)

            try:
                do_task(entry, parse_function, driver)
            except neo4j.exceptions.TransientError as e:
                logging.error("Could not resolve the error: %s", e)

        except KeyboardInterrupt as e:
            running = False
            raise e
        finally:
            q.task_done()
            icount += 1
            count += 1

    driver.close()

    # Create a new thread
    # Cicle the thread every 100 requests, to release the driver, memory e etc...
    if running:
        t = threading.Thread(target=worker, kwargs=dict(index=index, parse_function=parse_function, **kwargs))
        t.daemon = True
        t.start()

    # Nedded for exit thread
    return



def do_task(entry, parse_function, driver: neo4j.GraphDatabase):
    global total
    for retry in range(5):

        try:
            with driver.session() as session:
                transactions = session.read_transaction(parse_function, entry)

            if isinstance(transactions, list) and len(transactions) > 0:
                with driver.session() as session:
                    session.write_transaction(executer, transactions)

            break
        except KeyboardInterrupt as e:
            raise e
        except neo4j.exceptions.ConstraintError as e:
            print(e)
            return
        except Exception as e:
            time.sleep(0.500)
            if isinstance(e, neo4j.exceptions.TransientError):

                if retry > 3:
                    logging.error("neo4j.exceptions.TransientError: %s", e)
                    raise e

                #Deadlock, wait more time
                time.sleep(0.500)

            if retry > 3:
                logging.error("Could not process the registry: %s", json.dumps(entry))
                logging.error(e)
                logging.error(e.__class__)

                return


def status():
    global running, total, count
    p = 0
    with progress.Bar(label=" Importing ", expected_size=total) as bar:
        while running:
            if p != count: 
                bar.show(count)
                p = count
            time.sleep(0.1)

        bar.hide = True
        sys.stderr.write("\033[K")
        try:
            size = os.get_terminal_size(fd=os.STDOUT_FILENO)
        except:
            size = 50
        print((" " * size), file=sys.stderr, end='\r', flush=True)
                

def parse_file(filename: str, **kwargs):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    global running, total, count

    logging.getLogger().setLevel(logging.INFO)

    logging.info("Parsing bloodhound file: %s", filename)

    # Get meta registers
    meta = {}
    with open(filename, 'rb') as js:
        # Obtain meta tag
        js.seek(-0x100, os.SEEK_END)
        lastbytes = str(js.read(0x100))
        metatagstr = re.search('("meta":(\s+)?{.*})}', lastbytes, re.MULTILINE | re.IGNORECASE).group(1)
        metatag = json.loads('{' + metatagstr + '}')
        meta = metatag.get('meta',None)

    if meta is None:
        logging.error("Error parsing Meta tag.")
        return

    obj_type = meta.get('type', None)
    total = meta.get('count', -1)

    if total == -1:
        logging.error("Error getting total of registers.")
        return

    parsing_map = {
        'computers': parse_computer,
        'users': parse_user,
        'groups': parse_group,
        'domains': parse_domain,
        'gpos': parse_gpo,
        'ous': parse_ou
    }

    parse_function = None
    try:
        parse_function = parsing_map[obj_type]
    except KeyError:
        logging.error("Parsing function for object type: %s was not found.", obj_type)
        return

    threads = int(total/500)

    if threads > 5:
        threads = 5

    if threads <= 0:
        threads = 1

    logging.info("Starting %s threads", threads)

    # Status Thread
    t = threading.Thread(target=status)
    t.daemon = True
    t.start()

    # worker threads
    for i in range(threads):
        t = threading.Thread(target=worker, kwargs=dict(index=i, parse_function=parse_function, **kwargs))
        t.daemon = True
        t.start()

    with q.mutex:
        q.queue.clear()


    logging.getLogger().setLevel(logging.ERROR)

    with open(filename, 'r', encoding="latin-1", errors="surrogateescape") as f:
        objs = ijson.items(f, 'data.item')
        try:
            for entry in objs:
                q.put(entry)
                #do_task(entry, parse_function, driver)

        except KeyboardInterrupt as e:
            running = False
    

    while running:
        try:
            l = len(q.queue)
            if l > 0:
                #print((" " * 80) + str(l), end='\r', flush=True)
                time.sleep(0.3 if l < 1000 else 5)
            else:
                running=False
        except KeyboardInterrupt as e:
            logging.error("interrupted by user")
            with q.mutex:
                q.queue.clear()

            running = False

    logging.getLogger().setLevel(logging.INFO)

    logging.info("Parsed %d out of %d records in %s.", count, total, filename)

    logging.info("Completed file: %s", filename)
