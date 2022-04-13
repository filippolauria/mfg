# -*- coding: utf-8 -*-
#
#  blueprints/main.py
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

from datetime import date, timedelta, datetime
from flask import Blueprint, request, redirect, render_template, flash, url_for
from flask_login import current_user, logout_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.config import account_disabled_groupname, password_expired_groupname
from mfg.forms import UidForm, SearchByUsernameForm, FirstAccessForm, PasswordForm, UserPersonInfoForm
from mfg.models import User, Organization, Group, Radcheck, Radgroupcheck, Token, ActionEnum

from mfg.helpers.config import ConfigManager, OrganizationConfigManager
from mfg.helpers.decorators import is_authenticated, is_admin_or_contact_person, is_regular_user
from mfg.helpers.hashes import make_hash
from mfg.helpers.utils import flash_errors, make_token
from mfg.helpers.validators import MinMaxLengthAndEqualIfRequired



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
        return render_template('index.html', conf=ConfigManager)

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
                new_user = User(email=form.email.data, firstname=form.firstname.data, lastname=form.lastname.data,
                                username=username, self_renew=True, is_admin=True,
                                created_on=date.today(), is_active=True)
                new_user.organization = new_organization
                db.session.add(new_user)

                # we create the attribute for the password
                # ConfigManager.get returns the default since here this property has not been set yet in the db
                hash_type = ConfigManager.get('hashing.algorithm')
                hash_ = make_hash(form.password1.data, hash_type)
                radcheck_record = Radcheck(username=username, attribute=hash_type, op=':=', value=hash_)
                db.session.add(radcheck_record)

                # we create expire and disable groups
                expire_group = Group(groupname=password_expired_groupname)
                db.session.add(expire_group)

                disable_group = Group(groupname=account_disabled_groupname)
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
                ConfigManager.set_default()

                # set organization configuration defaults (triggers SQLAlchemyError exception)
                OrganizationConfigManager(new_organization).set_default()

                flash("The system has been setup, now you can login", 'success')
                return redirect(url_for('auth.login'))

            except SQLAlchemyError as e:
                # TODO rollback (?)
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    return render_template('index.html', conf=ConfigManager, form=form)


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
    users = User.query.filter(User.organization_id.in_(org_ids)).all()

    # we start count how many users are...
    counters = {}

    # expired...
    counters['expired'] = User.query.with_entities(User.id).join(User.groups).filter(
                            (Group.groupname == password_expired_groupname) &
                            (User.organization_id.in_(org_ids))).distinct().count()
    # disabled...
    counters['disabled'] = User.query.with_entities(User.id).join(User.groups).filter(
                            (Group.groupname == account_disabled_groupname) &
                            (User.organization_id.in_(org_ids))).distinct().count()

    # we get the number of days before the account expiration.
    # During this time the account is considered as "expiring"
    expires_in_days = ConfigManager.get('alert.when.password.expires.in.days')

    expires_on = date.today() + timedelta(days=expires_in_days)
    counters['expiring'] = User.query.with_entities(User.id).filter(
                            (User.expires_on <= expires_on) &
                            (User.organization_id.in_(org_ids))).distinct().count()

    # we count how many organizations we have
    counters['organization'] = Organization.query.with_entities(Organization.id).count()

    # we count how many contact persons we have
    counters['contact_person'] = User.query.with_entities(User.id).filter(
                                    User.organizations.any(
                                        Organization.id.in_(org_ids))).distinct().count()

    return render_template('privileged_dashboard.html', conf=ConfigManager, current_user=current_user, users=users, form=form,
                        counters=counters)
    

@main.route('/user/dashboard', methods=['GET', 'POST'])
@is_authenticated
def regular_dashboard():
    """
    This view allows the current regular user to see their information.
    """
    form = PasswordForm(request.form)

    formName = UserPersonInfoForm(request.form)
   

    #after changing password
    if request.method == 'POST':
        
        if (not form.validate() and form.password1.data and form.password2.data):
            flash_errors(form)
            #TODO
        
        
        elif form.password1.data and form.password2.data:

            try:

                form.password1.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method', 'password_by_admin', equalto_field_name='password2')]
                form.password2.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method', 'password_by_admin')]
                
                hash_type = ConfigManager.get('hashing.algorithm')
                radcheck_record = db.session.query(Radcheck).filter((Radcheck.username == current_user.username) & (Radcheck.attribute == hash_type)).first()
                radcheck_record.value = make_hash(form.password1.data, hash_type) 
                
                db.session.commit()
                
                flash("Password successfully changed!",'success')
            
            except SQLAlchemyError as e:
                flash(str(e), 'danger')
            
           
            formName.firstname.data = current_user.firstname
            formName.lastname.data = current_user.lastname

            return render_template('regular_dashboard.html', conf=ConfigManager, current_user=current_user, form=form, formName=formName)
        
        elif formName.firstname.data and formName.lastname.data:
            #replace names
            try:
                
                user = db.session.query(User).filter(( User.username == current_user.username) & (User.lastname == current_user.lastname)).first()
                
                user.firstname = formName.firstname.data
                user.lastname = formName.lastname.data
                
                db.session.commit()
                
                flash(f"Name successfully changed!",'success')
            
            except SQLAlchemyError as e:
                flash(str(e), 'danger')

            return render_template('regular_dashboard.html', conf=ConfigManager, current_user=current_user, form=form, formName=formName)
           

    formName.firstname.data = current_user.firstname
    formName.lastname.data = current_user.lastname
    
    return render_template('regular_dashboard.html',conf=ConfigManager, current_user=current_user, form=form, formName=formName)
