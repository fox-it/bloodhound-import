import argparse
import logging
from bloodhound_import import database
from bloodhound_import.importer import parse_file, add_constraints
from neo4j.exceptions import ClientError


def main():
    """
        Main function
    """
    argparser = argparse.ArgumentParser("bloodhound-import.py")
    argparser.add_argument("files", help="Files to parse.", nargs="+")
    argparser.add_argument("-du", "--database-user", help="Username to connect to neo4j, if not specified will try to auto detect a config file.")
    argparser.add_argument("-dp", "--database-password", help="Password to connect to neo4j, if not specified will try to auto detect a config file.")
    argparser.add_argument("--database", help="The host neo4j is running on.", default="localhost")
    argparser.add_argument("-p", "--port", help="Port of neo4j", default=7687)
    argparser.add_argument("-s", "--scheme", help="URI Scheme used to communicate with neo4j", default="bolt")
    argparser.add_argument("-v", "--verbose", help="Verbose output", action='store_true')
    arguments = argparser.parse_args()

    if arguments.database_password is None:
        arguments.database_user, arguments.database_password = database.detect_db_config()
        if arguments.database_password is None:
            logging.error('Error: Could not autodetect the Neo4j database credentials from your BloodHound config. Please specify them manually')
            return

    logging.basicConfig(format="[%(levelname)s] %(asctime)s - %(message)s")
    if arguments.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    
    conn_data = dict(
        ip=arguments.database,
        port=arguments.port,
        scheme=arguments.scheme,
        user=arguments.database_user, 
        password=arguments.database_password
    )

    driver = database.init_driver(**conn_data)
    try:
        try:
            with driver.session() as session:
                logging.debug("Adding constraints to the neo4j database")
                session.write_transaction(add_constraints)
        except ClientError:
            pass
    finally:
        driver.close()

    logging.info("Parsing %s files", len(arguments.files))
    for filename in arguments.files:
        parse_file(filename, **conn_data)

    logging.info("Done")

    exit(0)

if __name__ == "__main__":
    main()

