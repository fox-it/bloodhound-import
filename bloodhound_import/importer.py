"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

from dataclasses import dataclass
from tempfile import NamedTemporaryFile
from zipfile import ZipFile
from os.path import basename
import codecs
import ijson
import logging
import neo4j


@dataclass
class Query:
    query: str
    properties: dict


SYNC_COUNT = 100


def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{objectid: prop.source}}) SET n:{0} MERGE (m:Base {{objectid: prop.target}}) SET m:{1} MERGE (n)-[r:{2} {3}]->(m)'
    return insert_query.format(source_label, target_label, edge_type, edge_props)


async def process_ace_list(ace_list: list, objectid: str, objecttype: str, tx: neo4j.Transaction) -> None:
    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']

        if objectid == principal:
            continue

        query = build_add_edge_query(principaltype, objecttype, right, '{isacl: true, isinherited: prop.isinherited}')
        props = dict(
            source=principal,
            target=objectid,
            isinherited=entry['IsInherited'],
        )
        await tx.run(query, props=props)


async def process_spntarget_list(spntarget_list: list, objectid: str, tx: neo4j.Transaction) -> None:
    for entry in spntarget_list:
        query = build_add_edge_query('User', 'Computer', 'WriteSPN', '{isacl: false, port: prop.port}')
        props = dict(
            source=objectid,
            target=entry['ComputerSID'],
            port=entry['Port'], 
        )
        await tx.run(query, props=props)


async def add_constraints(tx: neo4j.Transaction):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction.
    """
    await tx.run('CREATE CONSTRAINT base_objectid_unique ON (b:Base) ASSERT b.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT computer_objectid_unique ON (c:Computer) ASSERT c.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT domain_objectid_unique ON (d:Domain) ASSERT d.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT group_objectid_unique ON (g:Group) ASSERT g.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT user_objectid_unique ON (u:User) ASSERT u.objectid IS UNIQUE')
    await tx.run("CREATE CONSTRAINT ON (c:User) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


async def parse_ou(tx: neo4j.Transaction, ou: dict):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    identifier = ou['ObjectIdentifier'].upper()
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:OU SET n += prop.map'
    props = {'map': ou['Properties'], 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in ou and ou['Aces'] is not None:
        await process_ace_list(ou['Aces'], identifier, "OU", tx)

    if 'ChildObjects' in ou and ou['ChildObjects']:
        targets = ou['ChildObjects']
        for target in targets:
            query = build_add_edge_query('OU', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))

    if 'Links' in ou and ou['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in ou['Links']:
            await tx.run(query, props=dict(source=identifier, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced']))

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in ou and ou['GPOChanges']:
        gpo_changes = ou['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    query = build_add_edge_query(target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}')
                    for computer in affected_computers:
                        await tx.run(query, props=dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier']))


async def parse_gpo(tx: neo4j.Transaction, gpo: dict):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction
        gpo {dict} -- Single gpo object.
    """
    identifier = gpo['ObjectIdentifier']

    query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:GPO SET n += prop.map'
    props = {'map': gpo['Properties'], 'source': identifier}
    await tx.run(query, props=props)

    if "Aces" in gpo and gpo["Aces"] is not None:
        await process_ace_list(gpo['Aces'], identifier, "GPO", tx)


async def parse_computer(tx: neo4j.Transaction, computer: dict):
    """Parse a computer object.

    Arguments:
        session {neo4j.Transaction} -- Neo4j transaction
        computer {dict} -- Single computer object.
    """
    identifier = computer['ObjectIdentifier']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Computer SET n += prop.map'
    props = {'map': computer['Properties'], 'source': identifier}

    await tx.run(property_query, props=props)

    if 'PrimaryGroupSid' in computer and computer['PrimaryGroupSid']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        await tx.run(query, props=dict(source=identifier, target=computer['PrimaryGroupSid']))

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        query = build_add_edge_query('Computer', 'Group', 'MemberOf', '{isacl:false}')
        for entry in computer['AllowedToDelegate']:
            await tx.run(query, props=dict(source=identifier, target=entry['ObjectIdentifier']))

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
                query = build_add_edge_query(target['ObjectType'], 'Computer', edge_name, '{isacl:false, fromgpo: false}')
                await tx.run(query, props=dict(source=target['ObjectIdentifier'], target=identifier))

    # (Session type, source)
    session_types = [
        ('Sessions', 'netsessionenum'),
        ('PrivilegedSessions', 'netwkstauserenum'),
        ('RegistrySessions', 'registry'),
    ]

    for session_type, source in session_types:
        if session_type in computer and computer[session_type]['Results']:
            query = build_add_edge_query('Computer', 'User', 'HasSession', '{isacl:false, source:"%s"}' % source)
            for entry in computer[session_type]['Results']:
                await tx.run(query, props=dict(target=entry['UserSID'], source=identifier))

    if 'Aces' in computer and computer['Aces'] is not None:
        await process_ace_list(computer['Aces'], identifier, "Computer", tx)


async def parse_user(tx: neo4j.Transaction, user: dict):
    """Parse a user object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    identifier = user['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:User SET n += prop.map'
    props = {'map': user['Properties'], 'source': identifier}

    await tx.run(property_query, props=props)

    if 'PrimaryGroupSid' in user and user['PrimaryGroupSid']:
        query = build_add_edge_query('User', 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=identifier, target=user['PrimaryGroupSid']))

    if 'AllowedToDelegate' in user and user['AllowedToDelegate']:
        query = build_add_edge_query('User', 'Computer', 'AllowedToDelegate', '{isacl: false}')
        for entry in user['AllowedToDelegate']:
            await tx.run(query, props=dict(source=identifier, target=entry['ObjectIdentifier']))

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        await process_ace_list(user['Aces'], identifier, "User", tx)

    if 'SPNTargets' in user and user['SPNTargets'] is not None:
        await process_spntarget_list(user['SPNTargets'], identifier, tx)


async def parse_group(tx: neo4j.Transaction, group: dict):
    """Parse a group object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        group {dict} -- Single group object from the bloodhound json.
    """
    properties = group['Properties']
    identifier = group['ObjectIdentifier']
    members = group['Members']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Group SET n += prop.map'
    props = {'map': properties, 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in group and group['Aces'] is not None:
        await process_ace_list(group['Aces'], identifier, "Group", tx)

    for member in members:
        query = build_add_edge_query(member['ObjectType'], 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=member['ObjectIdentifier'], target=identifier))


async def parse_domain(tx: neo4j.Transaction, domain: dict):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        domain {dict} -- Single domain object from the bloodhound json.
    """
    identifier = domain['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Domain SET n += prop.map'
    props = {'map': domain['Properties'], 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in domain and domain['Aces'] is not None:
        await process_ace_list(domain['Aces'], identifier, 'Domain', tx)

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
            await tx.run(query, props=props)

    if 'ChildObjects' in domain and domain['ChildObjects']:
        targets = domain['ChildObjects']
        for target in targets:
            query = build_add_edge_query('Domain', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))

    if 'Links' in domain and domain['Links']:
        query = build_add_edge_query('GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in domain['Links']:
            await tx.run(
                query,
                props=dict(source=identifier, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced'])
            )

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in domain and domain['GPOChanges']:
        gpo_changes = domain['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    query = build_add_edge_query(target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}')
                    for computer in affected_computers:
                        await tx.run(query, props=dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier']))

async def parse_container(tx: neo4j.Transaction, container: dict):
    """Parse a Container object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        container {dict} -- Single container object from the bloodhound json.
    """
    identifier = container['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Container SET n += prop.map'
    props = {'map': container['Properties'], 'source': identifier}

    await tx.run(property_query, props=props)

    if 'Aces' in container and container['Aces'] is not None:
        await process_ace_list(container['Aces'], identifier, "Container", tx)

    if 'ChildObjects' in container and container['ChildObjects']:
        targets = container['ChildObjects']
        for target in targets:
            query = build_add_edge_query('Container', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))


async def parse_zipfile(filename: str, driver: neo4j.Driver):
    """Parse a bloodhound zip file.

    Arguments:
        filename {str} -- ZIP filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    with ZipFile(filename) as zip_file:
       for file in zip_file.namelist():
            if not file.endswith('.json'):
                logging.info("File does not appear to be JSON, skipping: %s", file)
                continue

            with NamedTemporaryFile(suffix=basename(file)) as temp:
                temp.write(zip_file.read(file))
                temp.flush()
                await parse_file(temp.name, driver)


async def parse_file(filename: str, driver: neo4j.AsyncDriver):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- JSON filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    if filename.endswith('.zip'):
        logging.info("File appears to be a zip file, importing all containing JSON files..")
        await parse_zipfile(filename, driver)
        return

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        meta = ijson.items(f, 'meta')
        for o in meta:
            obj_type = o['type']
            total = o['count']

    parsing_map = {
        'computers': parse_computer,
        'containers': parse_container,
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
    objs = ijson.items(f, 'data.item')
    async with driver.session() as session:
        for entry in objs:
            try:
                await session.write_transaction(parse_function, entry)
                count = count + 1
            except neo4j.exceptions.ConstraintError as e:
                print(e)
            if count % ten_percent == 0:
                logging.info("Parsed %d out of %d records in %s.", count, total, filename)

    f.close()
    logging.info("Completed file: %s", filename)