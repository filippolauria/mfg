# -*- coding: utf-8 -*-
#
#  blueprints/radius.py
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

from flask import Blueprint, render_template, request, flash, abort
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import RadTableForm
from mfg.models import User, Group, Radcheck, Radreply, Radgroupcheck, Radgroupreply

from mfg.helpers.config import ConfigManager
from mfg.helpers.decorators import is_admin
from mfg.helpers.utils import flash_errors


radius = Blueprint('radius', __name__)


def radtable_helper(obj_id, RadiusModelClass, MfgModelClass, foreign_key_attr_name):
    """
    helper function for views that allow to list, create, edit and delete
    radcheck, radreply, radgroupcheck, radgroupreply attributes
    """

    # get the obj (user or group) associated with obj_id
    this_obj = db.session.query(MfgModelClass).get(obj_id)
    if not this_obj:
        # TODO log
        abort(404)

    # instantiate the form for editing/creating an attribute
    form = RadTableForm(request.form)
    if request.method == 'POST':
        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash_errors(form)
        else:
            # ... otherwise
            try:
                # we assign to name the username or groupname property retrieved from this_obj
                name = getattr(this_obj, foreign_key_attr_name)

                # if we do not have a posted attribute_id, we are creating a new one
                if not form.attribute_id.data:
                    element = RadiusModelClass(op=form.op.data, attribute=form.attribute.data, value=form.value.data)
                    setattr(element, foreign_key_attr_name, name)
                    db.session.add(element)

                    # we clear form data
                    form.attribute_id.data = ''
                    form.attribute.data = ''
                    form.op.data = ''
                    form.value.data = ''

                    # then prepare a message to be flashed
                    message = f"The attribute {element.attribute} has been successfully added"
                else:
                    # if we have a posted attribute_id
                    # we edit the attribute with that id
                    attribute_id = int(form.attribute_id.data)
                    element = db.session.query(RadiusModelClass).get(attribute_id)
                    setattr(element, foreign_key_attr_name, name)
                    element.op = form.op.data
                    element.attribute = form.attribute.data
                    element.value = form.value.data

                    # then we prepare the message to be flashed
                    message = f"The attribute {element.attribute} has been successfully updated"

                db.session.commit()
                flash(message, 'success')

            except ValueError:
                flash("The record you selected is not valid", 'danger')
            except SQLAlchemyError as e:
                # TODO rollback (?)
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # we create a dictionary of attributes to be used in a datalist element (HTML 5)
    used_attrs = db.session.query(RadiusModelClass).with_entities(RadiusModelClass.attribute).distinct().all()
    from mfg.helpers.radius import attributes as attrs, operators as ops
    attrs.extend([a.attribute for a in used_attrs])
    attrs = sorted(set(attrs))

    # the condition is specified on User.username (or Group.groupname),
    # which has to be equal to this_obj.username (or this_obj.groupname)
    condition = getattr(RadiusModelClass, foreign_key_attr_name) == getattr(this_obj, foreign_key_attr_name)
    elements = db.session.query(RadiusModelClass).filter(condition).all()

    return render_template('radius/radtable.html', conf=ConfigManager, current_user=current_user, obj=this_obj,
                           form=form, elements=elements, table=RadiusModelClass.__tablename__, attrs=attrs, ops=ops)


# ~ def delete_from_radtabled(RadiusModelClass, foreign_key_attr_name)

@radius.route('/radius/radcheck/manage/<int:uid>', methods=['GET', 'POST'])
@is_admin
def radcheck(uid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radcheck attributes
    """
    return radtable_helper(uid, Radcheck, User, 'username')


@radius.route('/radius/radreply/manage/<int:uid>', methods=['GET', 'POST'])
@is_admin
def radreply(uid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radreply attributes
    """
    return radtable_helper(uid, Radreply, User, 'username')


@radius.route('/radius/radgroupcheck/manage/<int:gid>', methods=['GET', 'POST'])
@is_admin
def radgroupcheck(gid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radgroupcheck attributes
    """
    return radtable_helper(gid, Radgroupcheck, Group, 'groupname')


@radius.route('/radius/radgroupreply/manage/<int:gid>', methods=['GET', 'POST'])
@is_admin
def radgroupreply(gid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radgroupreply attributes
    """
    return radtable_helper(gid, Radgroupreply, Group, 'groupname')
