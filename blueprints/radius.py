# -*- coding: utf-8 -*-
#
#  blueprints/radius.py
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

from flask import Blueprint, current_app, request, flash, abort
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import RadTableForm
from mfg.models import User, Group, Radcheck, Radreply, Radgroupcheck, Radgroupreply

from mfg.helpers.settings import GlobalSettingsManager
from mfg.helpers.decorators import is_admin
from mfg.helpers.utils import flash_errors, render_template


radius = Blueprint('radius', __name__)


def radtable_helper(obj_id, RadiusModelClass, MfgModelClass, foreign_key_attr_name, immutable):
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
            if immutable:
                message = "These records are immutable"
            else:
                # if it is not immutable we can proceed
                try:
                    # update the related object
                    this_obj.modifiedby = current_user
                    
                    # we assign to name the username or groupname property retrieved from this_obj
                    name = getattr(this_obj, foreign_key_attr_name)

                    # if we do not have a posted attribute_id, we are creating a new one
                    if not form.attribute_id.data:
                        record = RadiusModelClass(op=form.op.data, attribute=form.attribute.data, value=form.value.data)
                        setattr(record, foreign_key_attr_name, name)
                        db.session.add(record)

                        # we clear form data
                        form.attribute_id.data = ''
                        form.attribute.data = ''
                        form.op.data = ''
                        form.value.data = ''

                        # then prepare a message to be flashed
                        message = f"The attribute {record.attribute} has been successfully added"
                    else:
                        # if we have a posted attribute_id
                        # we edit the attribute with that id
                        attribute_id = int(form.attribute_id.data)
                        record = db.session.query(RadiusModelClass).get(attribute_id)
                        setattr(record, foreign_key_attr_name, name)
                        record.op = form.op.data
                        record.attribute = form.attribute.data
                        record.value = form.value.data

                        # then we prepare the message to be flashed
                        message = f"The attribute {record.attribute} has been successfully updated"

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
    records = db.session.query(RadiusModelClass).filter(condition).all()

    return render_template('radius/radtable.html', conf=GlobalSettingsManager, current_user=current_user, obj=this_obj,
                           form=form, records=records, table=RadiusModelClass.__tablename__, attrs=attrs, ops=ops,
                           immutable=immutable)


# ~ TODO def delete_from_radtabled(RadiusModelClass, foreign_key_attr_name):

@radius.route('/admin/radius/radcheck/manage/<int:uid>', methods=['GET', 'POST'])
@is_admin
def radcheck(uid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radcheck attributes
    """
    return radtable_helper(uid, Radcheck, User, 'username', False)


@radius.route('/admin/radius/radreply/manage/<int:uid>', methods=['GET', 'POST'])
@is_admin
def radreply(uid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radreply attributes
    """
    return radtable_helper(uid, Radreply, User, 'username', False)


@radius.route('/admin/radius/radgroupcheck/manage/<int:gid>', methods=['GET', 'POST'])
@is_admin
def radgroupcheck(gid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radgroupcheck attributes
    """
    this_group = db.session.query(Group).get(gid)
    if not this_group:
        # TODO log
        abort(404)

    groupname = str(this_group.groupname)
    immutable = bool(this_group.groupname == current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME'] or
                     this_group.groupname == current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME'])
    return radtable_helper(gid, Radgroupcheck, Group, 'groupname', immutable)


@radius.route('/admin/radius/radgroupreply/manage/<int:gid>', methods=['GET', 'POST'])
@is_admin
def radgroupreply(gid):
    """
    this view uses the radtable_helper function to list, create, edit or delete radgroupreply attributes
    """
    return radtable_helper(gid, Radgroupreply, Group, 'groupname', False)
