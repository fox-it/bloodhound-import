from setuptools import setup

setup(
    name='bloodhound_import',
    version='0.0.10',
    description='BloodHound import from python',
    license='MIT',
    classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
    ],
    author='Matthijs Gielen / Fox-IT',
    author_email='matthijs.gielen@fox-it.com',
    url='https://github.com/fox-it/bloodhound-import',
    packages=['bloodhound_import'],
    install_requires=['neo4j-driver', 'ijson', 'clint>=0.5.1', 'pytz==2022.1'],
    entry_points={
        'console_scripts': ['bloodhound-import=bloodhound_import:__main__']
    }
)
