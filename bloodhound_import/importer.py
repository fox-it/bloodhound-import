"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

from dataclasses import dataclass
import codecs
import ijson
import logging
import neo4j


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
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword"
}

SYNC_COUNT = 100


def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{objectid: prop.source}}) ON MATCH SET n:{0} ON CREATE SET n:{0} MERGE (m:Base {{objectid: prop.target}}) ON MATCH SET m:{1} ON CREATE SET m:{1} MERGE (n)-[r:{2} {3}]->(m)'
    return insert_query.format(source_label, target_label, edge_type, edge_props)


def process_ace_list(ace_list: list, objectid: str, objecttype: str, tx: neo4j.Transaction) -> None:
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
            query = build_add_edge_query(principaltype, objecttype, right, '{isacl: true, isinherited: prop.isinherited}')
            props = dict(
                source=principal,
                target=objectid,
                isinherited=entry['IsInherited'],
            )
            tx.run(query, props=props)


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


def parse_ou(tx: neo4j.Transaction, ou: dict):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    identifier = ou['ObjectIdentifier'].upper()
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:OU ON CREATE SET n:OU SET n += prop.map'
    props = {'map': ou['Properties'], 'source': identifier}
    tx.run(property_query, props=props)

    if 'Aces' in ou and ou['Aces'] is not None:
        process_ace_list(ou['Aces'], identifier, "OU", tx)

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
                tx.run(query, props=dict(source=identifier, target=target))

    if 'Links' in ou and ou['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in ou['Links']:
            tx.run(query, props=dict(source=identifier, target=gpo['Guid'].upper(), enforced=gpo['IsEnforced']))

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
                    tx.run(query, props=dict(target=computer, source=target['MemberId']))


def parse_gpo(tx: neo4j.Transaction, gpo: dict):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction
        gpo {dict} -- Single gpo object.
    """
    identifier = gpo['ObjectIdentifier']

    query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:GPO ON CREATE SET n:GPO SET n += prop.map'
    props = {'map': gpo['Properties'], 'source': identifier}
    tx.run(query, props=props)

    if "Aces" in gpo and gpo["Aces"] is not None:
        process_ace_list(gpo['Aces'], identifier, "GPO", tx)


def parse_computer(tx: neo4j.Transaction, computer: dict):
    """Parse a computer object.

    Arguments:
        session {neo4j.Transaction} -- Neo4j transaction
        computer {dict} -- Single computer object.
    """
    identifier = computer['ObjectIdentifier']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Computer ON CREATE SET n:Computer SET n += prop.map'
    props = {'map': computer['Properties'], 'source': identifier}

    tx.run(property_query, props=props)

    if 'PrimaryGroupSid' in computer and computer['PrimaryGroupSid']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        tx.run(query, props=dict(source=identifier, target=computer['PrimaryGroupSid']))

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        for entry in computer['AllowedToDelegate']:
            tx.run(query, props=dict(source=identifier, target=entry))

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
                tx.run(query, props=dict(source=target['MemberId'], target=identifier))

    if 'Sessions' in computer and computer['Sessions']:
        query = build_add_edge_query('Computer', 'User', 'HasSession', '{isacl:false}')
        for entry in computer['Sessions']:
            tx.run(query, props=dict(source=entry['UserId'], target=identifier))


    if 'Aces' in computer and computer['Aces'] is not None:
        process_ace_list(computer['Aces'], identifier, "Computer", tx)


def parse_user(tx: neo4j.Transaction, user: dict):
    """Parse a user object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    identifier = user['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:User ON CREATE SET n:User SET n += prop.map'
    props = {'map': user['Properties'], 'source': identifier}

    tx.run(property_query, props=props)

    if 'PrimaryGroupSid' in user and user['PrimaryGroupSid']:
        query = build_add_edge_query('User', 'Group', 'MemberOf', '{isacl: false}')
        tx.run(query, props=dict(source=identifier, target=user['PrimaryGroupSid']))

    if 'AllowedToDelegate' in user and user['AllowedToDelegate']:
        query = build_add_edge_query('User', 'Computer', 'AllowedToDelegate', '{isacl: false}')
        for entry in user['AllowedToDelegate']:
            tx.run(query, props=dict(source=identifier, target=entry))

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        process_ace_list(user['Aces'], identifier, "User", tx)


def parse_group(tx: neo4j.Transaction, group: dict):
    """Parse a group object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        group {dict} -- Single group object from the bloodhound json.
    """
    properties = group['Properties']
    identifier = group['ObjectIdentifier']
    members = group['Members']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Group ON CREATE SET n:Group SET n += prop.map'
    props = {'map': properties, 'source': identifier}
    tx.run(property_query, props=props)

    if 'Aces' in group and group['Aces'] is not None:
        process_ace_list(group['Aces'], identifier, "Group", tx)

    for member in members:
        query = build_add_edge_query(member['MemberType'], 'Group', 'MemberOf', '{isacl: false}')
        tx.run(query, props=dict(source=member['MemberId'], target=identifier))


def parse_domain(tx: neo4j.Transaction, domain: dict):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        domain {dict} -- Single domain object from the bloodhound json.
    """
    identifier = domain['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) ON MATCH SET n:Domain ON CREATE SET n:Domain SET n += prop.map'
    props = {'map': domain['Properties'], 'source': identifier}
    tx.run(property_query, props=props)

    if 'Aces' in domain and domain['Aces'] is not None:
        process_ace_list(domain['Aces'], identifier, 'Domain', tx)

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
            tx.run(query, props=props)

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
                tx.run(query, props=dict(source=identifier, target=target))

    if 'Links' in domain and domain['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in domain['Links']:
            tx.run(
                query,
                props=dict(source=identifier, target=gpo['Guid'].upper(), enforced=gpo['IsEnforced'])
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
                query = build_add_edge_query(target['MemberType'], 'Computer', edge_name,
                                             '{isacl: false, fromgpo: true}')
                for computer in domain['Computers']:
                    tx.run(query, props=dict(target=computer, source=target['MemberId']))


def parse_file(filename: str, driver: neo4j.GraphDatabase):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        meta = ijson.items(f, 'meta')
        for o in meta:
            obj_type = o['type']
            total = o['count']

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

    ten_percent = total // 10 if total > 10 else 1
    count = 0
    f = codecs.open(filename, 'r', encoding='utf-8-sig')
    objs = ijson.items(f, '.'.join([obj_type, 'item']))
    with driver.session() as session:
        for entry in objs:
            try:
                session.write_transaction(parse_function, entry)
                count = count + 1
            except neo4j.exceptions.ConstraintError as e:
                print(e)
            if count % ten_percent == 0:
                logging.info("Parsed %d out of %d records in %s.", count, total, filename)

    f.close()
    logging.info("Completed file: %s", filename)
