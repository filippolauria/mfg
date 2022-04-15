# -*- coding: utf-8 -*-
#
#  blueprints/settings.py
#
# Copyright 2022 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
#
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

from flask import Blueprint, render_template, redirect, url_for, request, abort, flash
from flask_wtf import FlaskForm
from flask_login import current_user
from mfg.helpers.config import ConfigManager, default_global_settings as dgs
from mfg.helpers.decorators import is_admin, is_admin_or_contact_person
from mfg import db
from sqlalchemy.exc import SQLAlchemyError
from mfg.models import GlobalSettings
from wtforms import IntegerField, StringField

settings = Blueprint('settings', __name__)
@settings.route('/admin/settings', methods=['GET', 'POST'])
@is_admin
def admin():
    # we retrieve all the settings from the database
    global_settings = db.session.query(GlobalSettings).all()
    
    # temporary form class for create a variable number of fields
    class F(FlaskForm):
        pass

    for s in global_settings:
        field_type = dgs[s.keyword]['coerce']
        
        if field_type is int:
            Field = IntegerField
        else:
            Field = StringField
            
        field_obj = Field(s.keyword, render_kw={'class': 'input', 'placeholder': s.keyword},
                          default=s.value, description=dgs[s.keyword]['desc'])
        setattr(F, s.keyword, field_obj)
    
    # instantiate the form
    form = F(request.form)
    
    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            try:
                for field in form:
                    if field.type in ['CSRFTokenField', 'HiddenField']:
                        continue
                    
                    setting = db.session.query(GlobalSettings).filter(GlobalSettings.keyword == field.name).first()
                    if not setting:
                        # TODO log
                        continue

                    setting.value = str(field.data)
                    db.session.commit()

            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # update selected choices
    # ~ form.field.data = [int(domain.id) for domain in this_organization.domains]
        
    return render_template('settings/global.html', conf=ConfigManager, current_user=current_user, form=form)

