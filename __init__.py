# -*- coding: utf-8 -*-
#
#  __init__.py
#
# Copyright 2021 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
#
# Computer and Communication Networks (CCN)
# Institute of Informatics and Telematics (IIT)
# Italian National Council of Research (CNR)
#
#
# This file is part of the Minimal FreeRADIUS GUI (MFG).
#
# The Minimal FreeRADIUS GUI (MFG) is free software: you can redistribute
# it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# The Minimal FreeRADIUS GUI (MFG) is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Minimal FreeRADIUS GUI (MFG).
# If not, see <http://www.gnu.org/licenses/>.
#

import json
import os
from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from werkzeug.routing import BaseConverter


# we instantiate our SQLAlchemy object called db, that we can use within our app.
# This will be set later at configuration time, using the init_app method
db = SQLAlchemy()

# we instantiate our Mail object called mail, that we can use within our app.
# This will be set later at configuration time, using the init_app method
mail = Mail()


def create_app():
    """ this function creates the app object needed by Flask """

    # we start creating the app object
    app = Flask(__name__, static_url_path='', static_folder='static', template_folder='templates')

    # we check if the config.json file exists and is readable
    config_json = os.path.join(app.root_path, 'config.json')
    if not (os.path.isfile(config_json) and os.access(config_json, os.R_OK)):
        print(f"[!] {config_json} does not exist or is not readable")
        return

    with open(config_json, 'r') as fd:
        try:
            json.load(fd)
        except Exception:
            print(f"[!] {config_json} is not a valid json file")
            return

    # we need this class in order to use regex as URL param
    class RegexConverter(BaseConverter):
        def __init__(self, url_map, *items):
            super(RegexConverter, self).__init__(url_map)
            self.regex = items[0]

    # we add our previously defined RegexConverter
    app.url_map.converters['regex'] = RegexConverter

    # we load application configuration from our config.json file
    app.config.from_file(config_json, load=json.load)

    # then we associate the app with our db object
    db.init_app(app)

    # and with our mail object
    mail.init_app(app)

    # we also instantiate our login manager, and finally associate the app to it
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    
    # we then import the User model
    from mfg.models import User

    # and define how to load an user
    @login_manager.user_loader
    def load_user(uid):
        return db.session.query(User).get(int(uid))

    # then we start registering all the blueprints

    # auth
    from mfg.blueprints.auth import auth as auth_bp
    app.register_blueprint(auth_bp)

    # main
    from mfg.blueprints.main import main as main_bp
    app.register_blueprint(main_bp)

    # organization
    from mfg.blueprints.organization import organization as organization_bp
    app.register_blueprint(organization_bp)

    # domain
    from mfg.blueprints.domain import domain as domain_bp
    app.register_blueprint(domain_bp)

    # user
    from mfg.blueprints.user import user as user_bp
    app.register_blueprint(user_bp)

    # group
    from mfg.blueprints.group import group as group_bp
    app.register_blueprint(group_bp)

    # contact_person
    from mfg.blueprints.contact_person import contact_person as contact_person_bp
    app.register_blueprint(contact_person_bp)

    # radius
    from mfg.blueprints.radius import radius as radius_bp
    app.register_blueprint(radius_bp)

    # settings
    from mfg.blueprints.settings import settings as settings_bp
    app.register_blueprint(settings_bp)

    return app
