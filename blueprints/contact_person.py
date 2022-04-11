# -*- coding: utf-8 -*-
#
#  blueprints/contact_person.py
#
# Copyright 2021 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
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

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import MultipleSelectForm
from mfg.models import Organization, User

from mfg.helpers.config import ConfigManager
from mfg.helpers.decorators import is_admin, is_admin_or_contact_person
from mfg.helpers.utils import flash_errors


contact_person = Blueprint('contact_person', __name__)


@contact_person.route('/admin/contact_person/list')
@is_admin_or_contact_person
def list():
    """
    this view allows an admin or a contact person to list contact persons
    """

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    # we select all the contact persons for the organizations which have been previously selected
    contact_persons = User.query.filter(User.organizations.any(Organization.id.in_(org_ids))).distinct().all()
    return render_template('contact_person/list.html', conf=ConfigManager, current_user=current_user,
                           contact_persons=contact_persons)


@contact_person.route('/admin/contact_person/<int:uid>', methods=['GET', 'POST'])
@is_admin
def associate_organizations(uid):
    """
    this view allows to associate organization(s) to a user.
    a user that has an associated organization, is a contact person for that organization
    """

    # we ensure that the associated user is valid
    this_user = db.session.query(User).get(uid)
    if not this_user:
        flash("Select an user from the following list", 'danger')
        return redirect(url_for('user.list'))

    # if it is valid, we get a list of organizations
    organizations = db.session.query(Organization).order_by(Organization.shortname).all()

    # then we preload form fields
    form = MultipleSelectForm(request.form)
    form.field.choices = [(int(o.id), o.name()) for o in organizations]
    form.field.label.text = "Select organizations"

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            try:
                # if the form is valid, we retrieve the selected organization objects
                selected_obj = []
                for obj_id in form.field.data:
                    obj = db.session.query(Organization).get(obj_id)
                    if not obj:
                        continue
                    selected_obj.append(obj)

                # then we update the relationship
                this_user.organizations = selected_obj

                # and ensure that this user is NOT an admin
                this_user.is_admin = False

                db.session.commit()

                # finally we prepare a message to be flashed back
                if len(selected_obj) == 0:
                    flash("All the organization associations have been removed", 'info')
                elif len(selected_obj) == 1:
                    flash("The organization has been associated successfully", 'success')
                else:
                    flash("The organizations have been associated successfully", 'success')
            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # we update form fields before rendering the page
    form.field.data = [int(o.id) for o in this_user.managed_organizations()]
    return render_template('contact_person/associate.html', conf=ConfigManager, current_user=current_user, form=form,
                           user=this_user)
