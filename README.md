# Minimal FreeRADIUS GUI (MFG)
Minimal FreeRADIUS GUI (MFG) is a web application written in Python 3 on top of [Flask](https://flask.palletsprojects.com/en/2.0.x/), [SQLAlchemy](https://www.sqlalchemy.org/) and [WTForms](https://wtforms.readthedocs.io/en/2.3.x/), which aims at managing an instance of [FreeRADIUS](https://freeradius.org/) (Version 3.x) with MySQL support ([installation guide](https://wiki.freeradius.org/guide/SQL-HOWTO-for-freeradius-3.x-on-Debian-Ubuntu)).

## development environment
This section describes the steps to quickly setup a development environment on an Ubuntu instance.
It is supposed that you have already installed FreeRADIUS and configured it with MySQL support as described [here](https://wiki.freeradius.org/guide/SQL-HOWTO-for-freeradius-3.x-on-Debian-Ubuntu).
### 0. create a development directory
Let's create our development directory:

    mkdir mfg_dev
    cd mfg_dev

### 1. create a Python 3 venv
Let's install python3 [venv](https://docs.python.org/3/library/venv.html) and activate it. 

    sudo apt update
    sudo apt install python3-venv
    python3 -m venv env
    source env/bin/activate

### 2. clone git repository and install dependencies
    sudo apt install libmysqlclient-dev
    git clone https://github.com/filippolauria/mfg.git
    cd mfg
    pip3 install -r requirements.txt
  
### 3. edit config.py
Edit config.py with your MySQL connection details. Also generate a `secret_key` with the following command:

    python3 -c 'from random import SystemRandom; from string import ascii_letters,digits;'\
    'print("".join(SystemRandom().choice(ascii_letters + digits) for _ in range(64)))'
   
Some example configurations are already specified.
### 4. execute the application in debug mode

    cd ..
    export FLASK_APP=mfg
    export FLASK_DEBUG=1
    flask run --host=127.0.0.1 --port=8888

