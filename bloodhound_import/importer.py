"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

from dataclasses import dataclass
import codecs
import json
import logging


@dataclass
class Query:
    query: str
    properties: dict


ACETYPE_MAP = {
    "All": "AllExtendedRights",
    "User-Force-Change-Password": "ForceChangePassword",
    "Member": "AddMember",
    "AddMember": "AddMember",
    "AllowedToAct": "AddAllowedToAct",
}

RIGHTS_MAP = {
    "GenericAll": "GenericAll",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "GenericWrite": "GenericWrite",
    "Owner": "Owns",
    "ReadLAPSPassword": "ReadLAPSPassword"
}

SYNC_COUNT = 100


def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str):
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{objectid: prop.source}}) ON MATCH SET n:{0} ON CREATE SET n:{0} MERGE (m:Base {{objectid: prop.target}}) ON MATCH SET m:{1} ON CREATE SET m:{1} MERGE (n)-[r:{2} {3}]->(m)'
    return insert_query.format(source_label, target_label, edge_type, edge_props)


def process_ace_list(ace_list: list, objectid: str, objecttype: str) -> list:
    queries = []
    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']
        acetype = entry['AceType']

        if objectid == principal:
            continue

        rights = []
        if acetype in ACETYPE_MAP:
            rights.append(ACETYPE_MAP[acetype])
        elif right == "ExtendedRight":
            rights.append(acetype)

        if right in RIGHTS_MAP:
            rights.append(RIGHTS_MAP[right])

        for right in rights:
            query = build_add_edge_query(objecttype, principaltype, right, '{isacl: true, isinherited: prop.isinherited}')
            props = dict(
                source=objectid,
                target=principal,
                isinherited=entry['IsInherited'],
            )
            queries.append(
                Query(query, props)
            )

    return queries


def add_constraints(tx):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Session} -- Neo4j session.
    """

    tx.run("CREATE CONSTRAINT ON (c:User) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


def parse_ou(tx, ou):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    queries = []
    identifier = ou['ObjectIdentifier'].upper()
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:OU ON CREATE SET n:OU SET n += prop.map'
    props = {'map': ou['Properties'], 'source': identifier}
    queries.append(Query(property_query, props))

    if 'Aces' in ou and ou['Aces'] is not None:
        queries.extend(process_ace_list(ou['Aces'], identifier, "OU"))

    options = [
        ('Users', 'User', 'Contains'),
        ('Computers', 'Computer', 'Contains'),
        ('ChildOus', 'OU', 'Contains'),
    ]

    for option, member_type, edge_name in options:
        if option in ou and ou[option]:
            targets = ou[option]
            for target in targets:
                query = build_add_edge_query('OU', member_type, edge_name, '{isacl: false}')
                queries.append(Query(query, dict(source=identifier, target=target)))

    if 'Links' in ou and ou['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in ou['Links']:
            queries.append(Query(query, dict(source=identifier, target=gpo['Guid'].upper(), enforced=gpo['IsEnforced'])))

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
                query = build_add_edge_query(target['MemberType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}')
                for computer in ou['Computers']:
                    queries.append(Query(query, dict(target=computer, source=target['MemberId'])))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def create_gpo_queries(tx, base_query, computers, objects, rel):
    """Creates the gpo queries.
    Arguments:
        tx {neo4j.Session} -- Neo4j session
        base_query {str} -- Query to base queries on.
        computers {list} -- Affected computers
        objects {list} -- Objects to apply the gpos
        rel {str} -- Name
    """
    count = 0
    for obj in objects:
        member = obj['Name']
        admin_type = obj['Type']
        query = base_query.format(admin_type, rel)
        for computer in computers:
            tx.run(query, props={"comp": computer, "member": member})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()


def parse_gpo(tx, gpo):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        gpo {dict} -- Single gpo object.
    """
    queries = []
    identifier = gpo['ObjectIdentifier']

    query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:GPO ON CREATE SET n:GPO SET n += prop.map'
    props = {'map': gpo['Properties'], 'source': identifier}
    queries.append(Query(query, props))

    if "Aces" in gpo and gpo["Aces"] is not None:
        queries.extend(process_ace_list(gpo['Aces'], identifier, "GPO"))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def parse_computer(tx, computer):
    """Parse a computer object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        computer {dict} -- Single computer object.
    """
    queries = []
    identifier = computer['ObjectIdentifier']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Computer ON CREATE SET n:Computer SET n += prop.map'
    props = {'map': computer['Properties'], 'source': identifier}

    queries.append(Query(property_query, props))

    if 'PrimaryGroupSid' in computer and computer['PrimaryGroupSid']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        queries.append(Query(query, dict(source=identifier, target=computer['PrimaryGroupSid'])))

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        for entry in computer['AllowedToDelegate']:
            queries.append(Query(query, dict(source=identifier, target=entry)))

    options = [
        ('AllowedToAct', 'AllowedToAct'),
        ('LocalAdmins', 'AdminTo'),
        ('RemoteDesktopUsers', 'CanRDP'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('PSRemoteUsers', 'CanPSRemote')
    ]

    for option, edge_name in options:
        if option in computer and computer[option]:
            targets = computer[option]
            for target in targets:
                query = build_add_edge_query(target['MemberType'], 'Computer', edge_name, '{isacl:false, fromgpo: false}')
                queries.append(Query(query, dict(source=target['MemberId'],target=identifier)))

    if 'Sessions' in computer and computer['Sessions']:
        query = build_add_edge_query('Computer', 'User', 'HasSession', '{isacl:false}')
        for entry in computer['Sessions']:
            queries.append(Query(query, dict(source=entry['MemberId'], target=identifier)))

    if 'Aces' in computer and computer['Aces'] is not None:
        queries.extend(process_ace_list(computer['Aces'], identifier, "Computer"))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def parse_user(tx, user):
    """Parse a user object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    queries = []

    identifier = user['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:User ON CREATE SET n:User SET n += prop.map'
    props = {'map': user['Properties'], 'source': identifier}

    queries.append(Query(property_query, props))

    if 'PrimaryGroupSid' in user and user['PrimaryGroupSid']:
        query = build_add_edge_query('User', 'Group', 'MemberOf', '{isacl: false}')
        queries.append(Query(query, dict(source=identifier, target=user['PrimaryGroupSid'])))

    if 'AllowedToDelegate' in  user and user['AllowedToDelegate']:
        query = build_add_edge_query('User', 'Computer', 'AllowedToDelegate', '{isacl: false}')
        for entry in user['AllowedToDelegate']:
            queries.append(Query(query, dict(source=identifier, target=entry)))

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        queries.extend(process_ace_list(user['Aces'], identifier, "User"))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def parse_group(tx, group):
    """Parse a group object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        group {dict} -- Single group object from the bloodhound json.
    """
    queries = []
    properties = group['Properties']
    identifier = group['ObjectIdentifier']
    aces = group['Aces']
    members = group['Members']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Group ON CREATE SET n:Group SET n += prop.map'
    props = {'map': properties, 'source': identifier}

    queries.append(Query(property_query, props))

    if 'Aces' in group and group['Aces'] is not None:
        queries.extend(process_ace_list(group['Aces'], identifier, "Group"))

    for member in members:
        query = build_add_edge_query('Group', member['MemberType'], 'MemberOf', '{isacl: false}')
        queries.append(Query(query, dict(source=identifier, target=member['MemberId'])))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def parse_domain(tx, domain):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        domain {dict} -- Single domain object from the bloodhound json.
    """
    queries = []
    identifier = domain['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Domain ON CREATE SET n:Domain SET n += prop.map'
    props = {'map': domain['Properties'], 'source': identifier}
    queries.append(Query(property_query, props))

    if 'Aces' in domain and domain['Aces'] is not None:
        queries.extend(process_ace_list(domain['Aces'], identifier, 'Domain'))

    trust_map = {0: 'ParentChild', 1: 'CrossLink', 2: 'Forest', 3: 'External', 4: 'Unknown'}
    if 'Trusts' in domain and domain['Trusts'] is not None:
        query = build_add_edge_query('Domain', 'Domain', 'TrustedBy', '{sidfiltering: prop.sidfiltering, trusttype: prop.trusttype, transitive: prop.transitive, isacl: false}')
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
            queries.append(Query(query, props))

    options = [
        ('Users', 'User', 'Contains'),
        ('Computers', 'Computer', 'Contains'),
        ('ChildOus', 'OU', 'Contains'),
    ]

    for option, member_type, edge_name in options:
        if option in domain and domain[option]:
            targets = domain[option]
            for target in targets:
                query = build_add_edge_query('OU', member_type, edge_name, '{isacl: false}')
                queries.append(Query(query, dict(source=identifier, target=target)))

    if 'Links' in domain and domain['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in domain['Links']:
            queries.append(
                Query(query, dict(source=identifier, target=gpo['Guid'].upper(), enforced=gpo['IsEnforced'])))

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
                query = build_add_edge_query(target['MemberType'], 'Computer', edge_name,
                                             '{isacl: false, fromgpo: true}')
                for computer in domain['Computers']:
                    queries.append(Query(query, dict(target=computer, source=target['MemberId'])))

    for entry in queries:
        tx.run(entry.query, props=entry.properties)


def chunks(l, n):
    """Creates chunks from a list.
    From: https://stackoverflow.com/a/312464

    Arguments:
        l {list} -- List to chunk
        n {int} -- Size of the chunks.
    """

    for i in range(0, len(l), n):
        yield l[i:i + n]


def parse_file(filename, driver):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    obj_type = data['meta']['type']
    total = data['meta']['count']

    parsing_map = {
        'computers': parse_computer,
        'users': parse_user,
        'groups': parse_group,
        'domains': parse_domain,
        'gpos': parse_gpo,
        'ous': parse_ou
    }

    # Split the data into chunks, fixing some bugs with memory usage.
    data_chunks = chunks(data[obj_type], 1000)
    count = 0

    parse_function = None
    try:
        parse_function = parsing_map[obj_type]
    except KeyError:
        logging.error("Parsing function for object type: %s was not found.", obj_type)
        return

    for chunk in data_chunks:
        # Create a new session per chunk.
        with driver.session() as session:
            for entry in chunk:
                count += 1
                session.write_transaction(parse_function, entry)

        logging.debug("%s/%s", count, total)

    logging.info("Completed file: %s", filename)
