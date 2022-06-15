# Minimal FreeRADIUS GUI (MFG)
Minimal FreeRADIUS GUI (MFG) is a web application written in Python 3 on top of [Flask](https://flask.palletsprojects.com/en/2.0.x/), [SQLAlchemy](https://www.sqlalchemy.org/) and [WTForms](https://wtforms.readthedocs.io/en/2.3.x/), which aims at managing an instance of [FreeRADIUS](https://freeradius.org/) (Version 3.x) with MySQL support ([installation guide](https://wiki.freeradius.org/guide/SQL-HOWTO-for-freeradius-3.x-on-Debian-Ubuntu)).

## development environment
This section describes the steps to quickly setup a development environment on a Debian 11 instance (equipped w/ [sudo](https://wiki.debian.org/sudo/)).
It is supposed that you have already installed FreeRADIUS and configured it with MySQL support as described [here](https://wiki.freeradius.org/guide/SQL-HOWTO-for-freeradius-3.x-on-Debian-Ubuntu).
Minimal FreeRADIUS GUI (MFG) has an interactive installation script that automatically creates a python3 [virtualenv](https://pypi.org/project/virtualenv/), installs all the required dependencies and generates the needed config.json file.
The installation script can be run by sudoers and when needed it will execute commands using sudo hence asking for the password.

### 0. install MFG

    sudo apt install git
    cd
    git clone https://github.com/filippolauria/mfg.git
    source mfg/setup/install.sh

### 1. execute MFG
    cd
    source mfg/env/bin/activate
    FLASK_APP=mfg FLASK_DEBUG=1 flask run --host=127.0.0.1 --port=8888

