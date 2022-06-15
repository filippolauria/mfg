# -*- coding: utf-8 -*-
#
#  blueprints/group.py
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

from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import GroupForm, UidForm
from mfg.models import Group

from mfg.helpers.settings import GlobalSettingsManager
from mfg.helpers.decorators import is_admin
from mfg.helpers.utils import flash_errors, render_template


group = Blueprint('group', __name__)


@group.route('/admin/group/manage', methods=['GET', 'POST'])
@is_admin
def manage():
    """
    this view allow an admin to list, create, edit and delete groups
    """

    # instantiate the form for editing/creating a group
    form = GroupForm(request.form)
    if request.method == 'POST':
        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash_errors(form)
        else:
            # ... otherwise
            try:
                new_groupname = form.groupname.data
                add_group = bool(not form.group_id.data)

                if add_group:
                    # if we do not have a posted group_id, we are creating a new group
                    group = Group(groupname=new_groupname, createdby=current_user)
                    db.session.add(group)

                else:
                    # if we have a posted group_id
                    # we edit the attribute with that id
                    group_id = int(form.group_id.data)
                    group = db.session.query(Group).get(group_id)
                    old_groupname = group.groupname
                    group.groupname = new_groupname
                    group.modifiedby = current_user

                    # we also have to update groupcheck and groupreply tables (T)
                    for T in [Radgroupcheck, Radgroupreply]:
                        records = db.session.query(T).filter(T.attribute == old_groupname).all()
                        for record in records:
                            record.attribute = new_groupname

                db.session.commit()

                # we clear form data
                form.group_id.data = ''
                form.groupname.data = ''

                # we prepare the message to be flashed back to the admin
                message = f"Group {groupname} successfully " + ("added" if add_group else "updated")
                flash(message, 'success')

            except ValueError:
                # TODO log
                flash("The group you selected is not valid", 'danger')
            except SQLAlchemyError as e:
                # TODO log
                flash(str(e), 'danger')

    # retrieve the groups list
    groups = db.session.query(Group).all()

    form_delete = UidForm()
    return render_template('group/manage.html', conf=GlobalSettingsManager, current_user=current_user, groups=groups, form=form,
                           form_delete=form_delete)


@group.route('/admin/group/delete', methods=['POST'])
@is_admin
def delete():
    """
    csrf_token protected path to delete a group
    """

    # we instantiate a simple UidForm
    form = UidForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Select a group from the following list", "danger")
        # ... then we redirect to group.manage view
        return redirect(url_for('group.manage'))

    try:
        # we get the gid and cast it to integer
        gid = int(form.uid.data)
        this_group = db.session.query(Group).get(gid)

        # we cannot remove user deleted and user disabled group
        if (this_group.groupname == current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME'] or
            this_group.groupname == current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME']):
            flash("The selected group cannot be removed", "danger")
            return redirect(url_for('group.manage'))

        # we ensure that the group associated with the submitted gid is valid
        if not this_group:
            flash("Select a group from the following list", "danger")
            return redirect(url_for('group.manage'))

        db.session.delete(this_group)
        db.session.commit()
        flash("The group has been successfully deleted", "success")

    except ValueError:
        # TODO log security warning
        flash("The group you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        flash(str(e), 'danger')

    return redirect(url_for('group.manage'))
