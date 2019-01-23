# bloodhound-import

![Python 2.7 and 3 compatible](https://img.shields.io/badge/python-2.7%2C%203.x-blue.svg)

Bloodhound-import is a tool to import bloodhound json files into neo4j.

## Dependencies and installation
Bloodhound-import is compatible with python 2.7 and 3.5+. It requires the `neo4j-driver` library.

Install with `sudo python setup.py install`. `bloodhound-import` will be installed as a global command. Usage is as follows:

```bash
usage: bloodhound-import.py [-h] [-du DATABASE_USER] [-dp DATABASE_PASSWORD]
                            [--database DATABASE] [-p PORT] [-v]
                            files [files ...]
```

Example:
`bloodhound-import -du neo4j -dp neo4j ~/Desktop/SessionLoop_20190115133114*.json`

If the -du and -dp options are not specified, the tool will try to auto detect these values from the bloodhound config file.
