# -*- coding: utf-8 -*-
#
#  blueprints/settings.py
#
# Copyright 2022 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
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

from flask import Blueprint, request, flash, abort, redirect, url_for
from flask_login import current_user
from flask_wtf import FlaskForm

from mfg import db
from mfg.models import Organization, GlobalSettings, OrganizationSettings
from sqlalchemy.exc import SQLAlchemyError
from wtforms import IntegerField, StringField

from mfg.helpers.settings import GlobalSettingsManager, OrganizationSettingsManager, \
                                 default_global_settings, default_organization_settings
from mfg.helpers.decorators import is_admin, is_admin_or_contact_person
from mfg.helpers.utils import flash_errors, render_template


settings = Blueprint('settings', __name__)


def settings_table_helper(SettingsManager, settings_, default_settings, organization=None):
    def func(o, k, v):
        if o == None:
            GlobalSettingsManager.set(k, v)
            return

        OrganizationSettingsManager(o).set(k, v)

    # temporary form class for create a variable number of fields
    class F(FlaskForm):
        pass

    for s in settings_:
        field_type = default_settings[s.keyword]['coerce']

        if field_type is int:
            Field = IntegerField
        else:
            Field = StringField

        field_obj = Field(s.keyword, render_kw={'class': 'input', 'placeholder': s.keyword},
                          default=s.value, description=default_settings[s.keyword]['desc'])
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

                    func(organization, field.name, field.data)

                flash("Settings saved successfully.", "success")

            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    return render_template('settings/edit.html', conf=GlobalSettingsManager, current_user=current_user,
                           form=form, organization=organization)


@settings.route('/admin/organization_settings/<int:oid>', methods=['GET', 'POST'])
@is_admin_or_contact_person
def _organization(oid):
    try:
        this_organization = db.session.query(Organization).get(oid)

        if not this_organization:
            #TODO log
            abort(404)

        if not current_user.is_contact_person_for(this_organization):
            #TODO log
            abort(403)

        if not this_organization.settings:
            #TODO log
            OrganizationSettingsManager(this_organization).set_default()
            
        settings_ = this_organization.settings

        default_settings = default_organization_settings

        return settings_table_helper(OrganizationSettingsManager(this_organization),
                                     settings_, default_settings, this_organization)

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('main.privileged_dashboard'))


@settings.route('/admin/global_settings/manage', methods=['GET', 'POST'])
@is_admin
def _global():
    try:
        # we retrieve all the settings from the database
        settings_ = db.session.query(GlobalSettings).all()
        if not settings:
            #TODO log
            abort(404)

        default_settings = default_global_settings

        return settings_table_helper(GlobalSettingsManager, settings_, default_settings)

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('main.privileged_dashboard'))
