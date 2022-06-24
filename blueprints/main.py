# -*- coding: utf-8 -*-
#
#  blueprints/main.py
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


import os
import random
from datetime import date, timedelta
from flask import Blueprint, request, redirect, flash, url_for, current_app, abort
from flask_login import current_user, logout_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import SearchByUsernameForm, FirstAccessForm
from mfg.models import User, Organization, Domain, Group, Radcheck, Radgroupcheck, GlobalSettings

from mfg.helpers.settings import GlobalSettingsManager, OrganizationSettingsManager
from mfg.helpers.decorators import is_authenticated, is_admin_or_contact_person
from mfg.helpers.hashes import make_hash
from mfg.helpers.utils import flash_errors, render_template, random_password as generate_random_password


main = Blueprint('main', __name__)


@main.route('/', methods=['GET', 'POST'])
def index():
    """
    root view of the application. If the application is started for the first time,
    the database schema is created and the configuration GUI is displayed.
    Otherwise a welcome message is printed
    """

    # if tables do not exist, we create them
    db.create_all()

    # we get a list of users and organizations
    users = db.session.query(User).all()
    organizations = db.session.query(Organization).all()

    # if we have at least one user and one organization we render the welcome message
    # TODO make the welcome message editable
    if users and organizations:
        if request.form:
            # TODO log that someone is attempting to execute this action
            pass

        return render_template('index.html', conf=GlobalSettingsManager)

    # we logout an (improbable) logged in user
    logout_user()

    # instantiate the FirstAccessForm
    form = FirstAccessForm(request.form)

    if request.method == 'POST':
        if not form.validate():
            # if the method is post and form does not validate,
            # we flash errors to the current admin or contact person
            flash_errors(form)
        else:
            # otherwise...
            try:
                # we add the new organization to the db
                new_organization = Organization(shortname=form.shortname.data, fullname=form.fullname.data)
                db.session.add(new_organization)

                # then we add the new user to the db
                username = form.username.data
                email = form.email.data
                new_user = User(firstname=form.firstname.data, lastname=form.lastname.data,
                                email=email, username=username, self_renew=True, is_admin=True,
                                created_on=date.today(), is_active=True)
                new_user.organization = new_organization
                db.session.add(new_user)
                
                # we add the domain name of the 1st administrator
                domain_name = email.split('@')[1]
                domain = Domain(domain_name=domain_name, createdby=new_user)
                db.session.add(domain)
                
                # we associate the domain name to administrator's organization
                new_organization.domains = [domain]

                # we create the attribute for the password
                # GlobalSettingsManager.get returns the default since here this property has not been set yet in the db
                hash_type = GlobalSettingsManager.get('hashing.algorithm')
                hash_ = make_hash(form.password1.data, hash_type)
                radcheck_record = Radcheck(username=username, attribute=hash_type, op=':=', value=hash_)
                db.session.add(radcheck_record)

                # we create expire and disable groups
                expire_group = Group(groupname=current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME'],
                                     createdby=new_user)
                db.session.add(expire_group)

                disable_group = Group(groupname=current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME'],
                                      createdby=new_user)
                db.session.add(disable_group)

                expire_radgroupcheck = Radgroupcheck(groupname=expire_group.groupname, attribute='Auth-Type',
                                                     op=':=', value='Reject')
                db.session.add(expire_radgroupcheck)
                disable_radgroupcheck = Radgroupcheck(groupname=disable_group.groupname, attribute='Auth-Type',
                                                      op=':=', value='Reject')
                db.session.add(disable_radgroupcheck)

                # we commit the addition(s) to the db
                db.session.commit()

                # set global configuration defaults (triggers SQLAlchemyError exception)
                GlobalSettingsManager.set_default()
                
                # by default, we set the keyword 'smtp.email' with the domain name
                # of the freshly created administrator
                GlobalSettingsManager.set('smtp.email', domain_name)
                
                # set organization configuration defaults (triggers SQLAlchemyError exception)
                OrganizationSettingsManager(new_organization).set_default()

                flash("The system has been setup, now you can login", 'success')
                return redirect(url_for('auth.login'))

            except SQLAlchemyError as e:
                # TODO rollback (?)
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    return render_template('index.html', conf=GlobalSettingsManager, form=form)


@main.route('/user/dashboard', methods=['GET', 'POST'])
@is_authenticated
def regular_dashboard():
    """
    This view allows the current regular user to see their information.
    """
    return render_template('regular_dashboard.html', conf=GlobalSettingsManager, current_user=current_user)
    

@main.route('/admin/dashboard', methods=['GET', 'POST'])
@is_admin_or_contact_person
def privileged_dashboard():
    """
    dashboard view. This view shows application stats to admin(s) or contact person(s)
    """

    # we instantiate the form used for searching user by username
    form = SearchByUsernameForm()

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    # we get the list of all the user belonging to the selected organizations
    users = db.session.query(User).filter(User.organization_id.in_(org_ids)).all()

    # we start count how many users are...
    counters = {}

    # expired...
    counters['expired'] = User.query.with_entities(User.id).join(User.groups).filter(
                            (Group.groupname == current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME']) &
                            (User.organization_id.in_(org_ids))).distinct().count()
    # disabled...
    counters['disabled'] = User.query.with_entities(User.id).join(User.groups).filter(
                            (Group.groupname == current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME']) &
                            (User.organization_id.in_(org_ids))).distinct().count()

    # we get the number of days before the account expiration.
    # During this time the account is considered as "expiring"
    expires_in_days = GlobalSettingsManager.get('alert.when.password.expires.in.days')

    expires_on = date.today() + timedelta(days=expires_in_days)
    counters['expiring'] = User.query.with_entities(User.id).filter(
                            (User.expires_on <= expires_on) &
                            (User.organization_id.in_(org_ids))).distinct().count()

    # we count how many organizations we have
    # ~ counters['organization'] = Organization.query.with_entities(Organization.id).count()
    counters['organization'] = len(org_ids)

    # we count how many contact persons we have
    counters['contact_person'] = User.query.with_entities(User.id).filter(
                                    User.organizations.any(
                                        Organization.id.in_(org_ids))).distinct().count()

    return render_template('privileged_dashboard.html', conf=GlobalSettingsManager, current_user=current_user,
                           users=users, form=form, counters=counters)


@main.route('/admin/random_password', methods=['GET'])
def random_password():
    """
    an endpoint for creating a strong password starting from a dictionary file
    """

    p = generate_random_password()

    if not p:
        abort(500)

    return p
