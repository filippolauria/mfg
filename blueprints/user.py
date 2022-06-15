# -*- coding: utf-8 -*-
#
#  blueprints/user.py
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

from datetime import datetime, date, timedelta
from flask import Blueprint, current_app, redirect, url_for, request, flash, abort
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy_utils.functions import escape_like
from wtforms.widgets import NumberInput
from wtforms.validators import InputRequired, NumberRange

from mfg import db
from mfg.forms import UidForm, UserForm, PasswordForm, RecoverWithEmailForm, RecoverWithUsernameForm, \
                      SearchFiltersForm, SearchByUsernameForm, ChangePasswordForm, UserPersonInfoForm, \
                      SelectOrganizationForm, ChangeEmailForm
from mfg.models import Organization, ActionEnum, Token, User, Group, \
                       Radcheck, Radreply, Radacct, Radpostauth, SignupToken

from mfg.helpers.settings import GlobalSettingsManager, OrganizationSettingsManager, OrganizationsSettingsManager
from mfg.helpers.decorators import is_admin, is_admin_or_contact_person, is_authenticated
from mfg.helpers.email import send_password_reset, send_account_activation
from mfg.helpers.hashes import make_hash, check_password_hash
from mfg.helpers.utils import flash_errors, render_template, make_token
from mfg.helpers.validators import RequiredDateBetweenIfChecked, MinMaxLengthAndEqualIfRequired
from mfg.helpers.widgets import DateInput


user = Blueprint('user', __name__)


@user.route('/admin/user/search', methods=['GET', 'POST'])
@is_admin_or_contact_person
def search():
    """
    this view allows an admin or a contact person to search user by username
    """

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    # we instantiate the form used for searching user by username
    form = SearchByUsernameForm(request.form)

    # we populate the user datalist (HTML 5)
    user_datalist = db.session.query(User).with_entities(User.username).filter(
                                     User.organization_id.in_(org_ids)).order_by(User.lastname).all()

    users = None
    if request.method == 'POST':
        if not form.validate():
            # if the method is post and form does not validate we flash errors to the current admin or contact person
            flash_errors(form)
        else:
            # we escape the data provided by the current admin or contact person to avoid SQL-Injection
            param = "%" + escape_like(form.username.data) + "%"
            users = db.session.query(User).filter((User.username.like(param)) &
                                                  (User.organization_id.in_(org_ids))).order_by(User.lastname).all()

    return render_template('user/search.html', conf=GlobalSettingsManager, current_user=current_user, form=form, users=users,
                           user_datalist=user_datalist)


@user.route('/admin/user/list/<int:pagenum>', methods=['GET', 'POST'])
@user.route('/admin/user/list', methods=['GET', 'POST'])
@is_admin_or_contact_person
def list(pagenum=1):
    """
    This view allows the current admin or contact person to list users.
    The view is paginated (on pagenum param) and also allow to specify some search filter.
    """

    # we instantiate a simple UidForm which is used to delete an user by ID
    uid_form = UidForm()

    # we get a list of organization which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    organizations = current_user.managed_organizations()
    org_ids = [o.id for o in organizations]

    # we also prepare a list of choices (id, shortname) for populating the search_form organizations filter
    choices = [(int(o.id), o.shortname) for o in organizations]
    search_form = SearchFiltersForm(request.form)
    search_form.organizations.choices = choices

    # we get the number of days before the account expiration.
    # During this time the account is considered as "expiring"
    expires_in_days = GlobalSettingsManager.get('alert.when.password.expires.in.days')
    # we update the filter label
    search_form.expiring_soon.label.text = f"Show expiring in {expires_in_days} days"

    # we initialize some useful variables
    usernames = []
    expiring_soon = False
    expired = False
    disabled = False
    contact_persons = False

    if request.method == 'POST':
        if not search_form.validate():
            # if the method is post and form does not validate we flash errors to the current admin or contact person
            flash_errors(search_form)
        else:
            # we initialize the variables with data posted by the current admin or contact person
            expired = bool(search_form.expired.data)
            disabled = bool(search_form.disabled.data)
            expiring_soon = bool(search_form.expiring_soon.data)
            contact_persons = bool(search_form.contact_persons.data)

            # if we have to filter for expired or disabled users...
            if any([expired, disabled]):
                filters = []

                if expired:
                    filters.append(Group.groupname == current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME'])

                if disabled:
                    filters.append(Group.groupname == current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME'])

                # ... we build up an appropriate filter
                # that we pass to a db query...
                query = User.query.with_entities(User.username).join(User.groups).filter(db.or_(*filters)).distinct()
                # ... collecting the results in the result variable
                result = query.all()

                # we then update the list of unique usernames
                for r in result:
                    if r.username not in usernames:
                        usernames.append(r.username)

            # if we have to filter for expiring or contact persons...
            if any([expiring_soon, contact_persons]):
                filters = []

                if expiring_soon:
                    expires_on = date.today() + timedelta(days=expires_in_days)
                    filters.append(User.expires_on <= expires_on)

                if contact_persons:
                    filters.append(User.organizations.any(Organization.id.in_(org_ids)))

                # ... we build up an appropriate filter
                # that we pass to a db query...
                query = User.query.with_entities(User.username).filter(db.or_(*filters)).distinct()
                # ... collecting the results in the result variable
                result = query.all()

                # we then update the list of unique usernames
                for r in result:
                    if r.username not in usernames:
                        usernames.append(r.username)
    else:
        # if the method is GET we select all the organizations
        search_form.organizations.data = org_ids

    # we start building another query:
    # we start creating a filter for the selected organizations
    filters = [User.organization_id.in_(search_form.organizations.data)]

    # if we have to filter for expired, disabled, expiring or contact persons
    # we use the previously created list of usernames as a filter too
    if any([expired, disabled, expiring_soon, contact_persons]):
        filters.append(User.username.in_(usernames))

    # we get the allowed number of items per page
    items_per_page = GlobalSettingsManager.get('max.items.per.page')

    # finally we execute the query with the appropriate filters and paginate the result
    users = db.session.query(User).filter(db.and_(*filters)).order_by(User.lastname).paginate(page=pagenum,
                                                                                              per_page=items_per_page)
    return render_template('user/list.html', conf=GlobalSettingsManager, current_user=current_user, users=users,
                           uid_form=uid_form, search_form=search_form)


@user.route('/admin/user/toggle_account_status', methods=['POST'])
@is_admin_or_contact_person
def toggle_account_status():
    """
    csrf_token protected path to toggle account status for an user
    """
    
    try:
        # we instantiate a simple UidForm
        form = UidForm(request.form)
        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash("Select an user from the following list", "danger")
            # ... then we redirect to user list
            return redirect(url_for('user.list'))
        else:
            # we get the uid and cast it to integer
            uid = int(form.uid.data)
            this_user = db.session.query(User).get(uid)

            # we ensure that the associated user is valid...
            if not this_user:
                flash("Select an user from the following list", "danger")
                return redirect(url_for('user.list'))

            # account status can be toggled if:
            #  - current_user is an admin
            #  - current_user is a contact person. In this case:
            #     - current_user must have the permission to manage users belonging to this_user's organization
            #     - this_user should not be an administrator
            if current_user.can_manage(this_user) and not this_user.is_admin:
                groupname = current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME']

                # we get the disabled group from the db
                disabled_group = db.session.query(Group).filter(Group.groupname == groupname).first()

                # we enable/disable the account
                func = disabled_group.users.remove if this_user.in_disabled_group() else disabled_group.users.append
                func(this_user)

                db.session.commit()

                # we build the exit message
                message = "account with username " + this_user.username + " is now "
                message += "disabled" if this_user.in_disabled_group() else "enabled"
                flash(message, "success")

                return redirect(url_for('user.details', uid=uid))

    except ValueError:
        flash("The user you selected is not valid", "danger")
    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.list'))


@user.route('/admin/user/toggle_admin_status', methods=['POST'])
@is_admin
def toggle_admin():
    """
    csrf_token protected path to toggle admin status for an user
    """

    # we instantiate a simple UidForm
    form = UidForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Select an user from the following list", "danger")
        # ... then we redirect to user list
        return redirect(url_for('user.list'))

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        this_user = db.session.query(User).get(uid)

        # we ensure that the associated user is valid...
        if not this_user:
            flash("Select an user from the following list", 'danger')
            return redirect(url_for('user.list'))

        # ... and that the current admin is not trying to self-update its admin status
        if uid == current_user.id:
            flash("Only another admin can update your admin status", 'danger')
            return redirect(url_for('user.details', uid=uid))

        # we toggle the admin status
        this_user.is_admin = not bool(this_user.is_admin)

        # if we toggle the admin status, we eventually clear existing managed organizations
        if this_user.is_admin:
            this_user.organizations = []

        # we commit changes to db
        db.session.commit()

        # we build the exit message
        message = this_user.username
        message += " is now an administrator" if this_user.is_admin else " is not an administrator anymore"

        flash(message, "success")
        return redirect(url_for('user.details', uid=uid))

    except ValueError:
        flash("The user you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.list'))


@user.route('/admin/user/organization/change/<int:uid>', methods=['POST'])
@is_admin_or_contact_person
def change_organization(uid):
    """
    this view is used by an admin or a contact person to change user's first and/or last name
    """
    try:
        # retrieve the user object associated to the provided uid
        this_user = db.session.query(User).get(uid)

        if not this_user:
            # TODO log
            abort(404)

        if not current_user.can_manage(this_user):
            # TODO log
            abort(403)

        # we get a list of all of the organizations for which current_user is a contact person
        # if current_user is admin this list is filled with all the organizations
        managed_organizations = current_user.managed_organizations()

        form = SelectOrganizationForm()
        form.organization.choices = [(int(o.id), o.name()) for o in managed_organizations]
        form.organization.label.text = "Select the organization"

        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash("Invalid input", "danger")
            # ... we will redirect to user list later
        else:
            organization_id = int(form.organization.data)
            if (organization_id not in [o.id for o in managed_organizations] or
                organization_id == this_user.organization_id):
                # TODO log
                abort(403)

            # we update the relationship
            organization = db.session.query(Organization).get(organization_id)
            this_user.organization = organization

            # we commit changes to db
            db.session.commit()

            flash("User organization has been updated", "success")

    except ValueError:
        # TODO log security warning
        flash("The organization you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.details', uid=uid))


@user.route('/admin/user/email/change/<int:uid>', methods=['POST'])
@is_admin_or_contact_person
def change_email(uid):
    """
    this view is used by an admin or a contact person to change user's email address
    """
    # retrieve the user object associated to the provided uid
    this_user = db.session.query(User).get(uid)

    if not this_user:
        # TODO log
        abort(404)

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    if this_user.organization_id not in org_ids:
        # TODO log
        abort(403)

    form = ChangeEmailForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Invalid input", "danger")
        # ... we will redirect to user list later
    else:
        try:
            email = form.field.data

            # we check if this email, already exists
            email_exists = db.session.query(User).filter(User.email == email).all()

            if email_exists:
                message = "This email is already used"
                category = "danger"
            else:
                this_user.email = form.field.data

                # we commit changes to db
                db.session.commit()

                message = "User email has been updated"
                category = "success"

            flash(message, category)
        except SQLAlchemyError as e:
            # TODO rollback (?)
            # TODO replace the exception text with a custom error message
            # TODO log the exception (to db ?, to file ?)
            flash(str(e), 'danger')

    return redirect(url_for('user.details', uid=uid))


@user.route('/admin/user/personinfo/change/<int:uid>', methods=['POST'])
@is_admin_or_contact_person
def change_personinfo(uid):
    """
    this view is used by an admin or a contact person to change user's first and/or last name
    """

    try:
        # retrieve the user object associated to the provided uid
        this_user = db.session.query(User).get(uid)

        if not this_user:
            # TODO log
            abort(404)

        if not current_user.can_manage(this_user):
            # TODO log
            abort(403)

        form = UserPersonInfoForm(request.form)
        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash("Invalid input", "danger")
            # ... we will redirect to user list later
        else:

            this_user.firstname = form.firstname.data
            this_user.lastname = form.lastname.data

            # we commit changes to db
            db.session.commit()

            flash("User details have been updated", "success")

    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.details', uid=uid))


@user.route('/admin/user/delete', methods=['POST'])
@is_admin_or_contact_person
def delete():
    """
    csrf_token protected path to delete an user
    """

    # we instantiate a simple UidForm
    form = UidForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Select an user from the following list", "danger")
        # ... then we redirect to user list
        return redirect(url_for('user.list'))

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    # ~ org_ids = [x.id for x in current_user.managed_organizations()]

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        this_user = db.session.query(User).get(uid)

        # we ensure that the associated user is valid and that they belong to an allowed organization
        # ~ if not this_user or this_user.organization_id not in org_ids:
        if not (this_user and current_user.can_manage(this_user)):
            flash("Select an user from the following list", "danger")
            return redirect(url_for('user.list'))

        # we also ensure that current admin or contact person is not trying to delete themself
        if current_user.id == uid:
            flash("You cannot delete yourself", "danger")
            return redirect(url_for('user.list'))

        db.session.delete(this_user)
        db.session.commit()
        flash("User has been successfully deleted", "success")
    except ValueError:
        # TODO log security warning
        flash("The user you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.list'))


def forgot_password_helper(FormClass, field_name):
    """
    helper function for views that allow to recover password by username and by email
    """

    # we instantiate the right form
    form = FormClass(request.form)

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
            return render_template('user/forgot_password.html', conf=GlobalSettingsManager, current_user=current_user,
                                   form=form, field=field_name)

        try:
            # we select the right query to use (and the return message), according to the field_name value
            if field_name == 'email':
                this_user = db.session.query(User).filter_by(email=form.field.data).first()
                message = "An email containing recover instructions has been sent to the specified email address."
            else:
                field_name = 'username'
                this_user = db.session.query(User).filter_by(username=form.field.data).first()
                message = "An email containing recover instructions has been sent to the email address associated " \
                          "with the specified username."

            # if an this_user has been retrieved
            if this_user:
                # we delete all old tokens related to the selected user...
                db.session.query(Token).filter(Token.user_id == this_user.id).delete()

                # ... and add a new token for them
                hours = OrganizationSettingsManager(this_user.organization).get('token.expired.after.hours')
                token_expires_on = datetime.now() + timedelta(hours=hours)
                new_token = Token(token=make_token(), expires_on=token_expires_on, action=ActionEnum.reset,
                                  user_id=this_user.id)
                db.session.add(new_token)

                db.session.commit()

                # TODO send the email with the password reset URL
                send_password_reset(new_token)

            # we clear the field value, then flash the status message (even if we have not found a valid user)
            form.field.data = ""
            flash(message, "success")
        except SQLAlchemyError as e:
            # TODO replace the exception text with a custom error message
            # TODO log the exception (to db ?, to file ?)
            flash(str(e), 'danger')

    return render_template('user/forgot_password.html', conf=GlobalSettingsManager, current_user=current_user, form=form,
                           field=field_name)


@user.route('/user/forgot_password::username', methods=['GET', 'POST'])
def forgot_password_username():
    """
    this view uses the above helper for the password reset feature by providing a valid username.
    """
    return forgot_password_helper(RecoverWithUsernameForm, 'username')


@user.route('/user/forgot_password::email', methods=['GET', 'POST'])
def forgot_password_email():
    """
    this view uses the above helper for the password reset feature by providing a valid email address.
    """
    return forgot_password_helper(RecoverWithEmailForm, 'email')


@user.route('/user/<regex("[a-f0-9]{32}"):token>', methods=['GET', 'POST'])
def reset_or_activate(token):
    """
    this view allows to reset or activate an account, by providing a valid token
    """

    try:
        # we try to retrieve the associated token object
        this_token = db.session.query(Token).filter_by(token=token).first()

        # if the token is invalid, we return a HTTP 404 error
        if not this_token:
            # TODO log
            abort(404)

        # if the token has expired, we return a HTTP 410 error
        if this_token.is_expired():
            # TODO log
            abort(410)
    
        # we get the user object associated to this_token
        this_user = this_token.user
    
        # we instantiate the form for resetting the password or activating an account
        form = PasswordForm(request.form)
        if request.method == 'POST':
            if not form.validate():
                # if the method is post and form does not validate,
                # we flash errors to the current admin or contact person
                flash_errors(form)
                return render_template('user/reset_or_activate.html', conf=GlobalSettingsManager, this_user=this_user, form=form,
                                       token=this_token)
            
            # we try to hash with the chosen hashing algorithm the user password
            # both in case of account activation and in case of password reset
            hash_type = GlobalSettingsManager.get('hashing.algorithm')
            try:
                new_hash = make_hash(form.password1.data, hash_type)
            except ValueError:
                # TODO log => Hashing algorithm not supported. Aborting.
                abort(500)

            # we retrieve all password attributes
            attrs = db.session.query(Radcheck).filter((Radcheck.username == this_user.username) &
                                                      (Radcheck.attribute.like("%-Password")) &
                                                      (Radcheck.op == ':=')).all()

            # we try to ensure that user is not trying to reuse an old password (if any)
            if len(attrs) > 0:
                reused = this_user.is_reusing_the_old_password(form.password1.data)

                if reused:
                    flash("The new password cannot be the same as the old password", 'danger')
                    return render_template('user/reset_or_activate.html', conf=GlobalSettingsManager, this_user=this_user, form=form,
                                           token=this_token)
                                           
                # we delete all stale password-like check attributes
                db.session.query(Radcheck).filter((Radcheck.username == this_user.username) &
                                                  (Radcheck.attribute.like("%-Password")) &
                                                  (Radcheck.op == ':=')).delete(synchronize_session=False)

            # and finally, in any case, we create the new password-like check attribute
            password_like_check_attribute = Radcheck(username=this_user.username, attribute=hash_type, op=':=',
                                                     value=new_hash)
            db.session.add(password_like_check_attribute)

            # we initialize the result message and activate the account (if needed)
            if this_token.action == ActionEnum.activate:
                message = f"Account for {this_user.username} has been successfully activated"
            else:
                message = f"Password for {this_user.username} has been successfully reset"
                
            this_user.is_active = True

            # we remove this token
            db.session.delete(this_token)
            db.session.commit()
            
            flash(message, 'success')

            # we redirect user to login page
            return redirect(url_for('auth.login'))

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return render_template('user/reset_or_activate.html', conf=GlobalSettingsManager, this_user=this_user, form=form,
                           token=this_token)


@user.route('/admin/user/create', methods=['GET', 'POST'])
@is_admin_or_contact_person
def create():
    """
    this view is used for creating other users
    """

    # we prepare the list of the organizations
    organizations = current_user.managed_organizations()
    choices = [(str(o.id), o.shortname) for o in organizations]

    # then we start instantiating the form
    form = UserForm(request.form)
    form.organization.choices = choices

    # passwords are required if the registration method is 'password_by_admin'
    form.password1.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method',
                                                                'password_by_admin', equalto_field_name='password2')]
    form.password2.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method', 'password_by_admin')]

    # we load maximum values for some configuration properties according to current user permissions
    if current_user.is_contact_person():
        settings_ = OrganizationsSettingsManager.get([o.id for o in organizations], 'account.disabled.after.months')
        max_disable_after = max(settings_) * 30

        settings_ = OrganizationsSettingsManager.get([o.id for o in organizations], 'password.expired.after.days')
        max_expires_after = max(settings_)

    else:
        max_disable_after = GlobalSettingsManager.get('max.account.disabled.after.months') * 30
        max_expires_after = GlobalSettingsManager.get('max.password.expired.after.days')

    # we set the maximum date for disable
    today = date.today()
    tomorrow = today + timedelta(days=1)
    # we use the previously retrieved variable: max_disable_after
    disable_on_date = today + timedelta(days=max_disable_after)
    form.disable_on.widget = DateInput(step=1, min=f"{tomorrow:%Y-%m-%d}", max=f"{disable_on_date:%Y-%m-%d}")
    form.disable_on.validators = [RequiredDateBetweenIfChecked('auto_disable', tomorrow, disable_on_date)]
    form.disable_on.data = disable_on_date

    # we set the expiration date
    form.expires_in.widget = NumberInput(step=1, min=1, max=max_expires_after)
    form.expires_in.validators.append(NumberRange(min=1, max=max_expires_after))
    # we use the previously retrieved variable: max_expires_after
    form.expires_in.data = max_expires_after

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
            return render_template('user/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form)

        try:
            self_renew = bool(form.self_renew.data)
            auto_disable = bool(form.auto_disable.data)

            organization_id = int(form.organization.data)
            organization = db.session.query(Organization).get(organization_id)

            is_active = bool(form.registration_method.data == 'password_by_admin')
            disable_on = form.disable_on.data
            
            expires_in = form.expires_in.data
            
            # we should specifically check values for users organization
            if not current_user.is_admin and current_user.is_contact_person_for(organization):
                max_disable_after = OrganizationSettingsManager(organization).get('account.disabled.after.months') * 30
                disable_on_date = today + timedelta(days=max_disable_after)
                if disable_on > disable_on_date:
                    max_disable_after = max_disable_after / 30
                    flash((
                            "You have chosen an invalid date for the account self-disabling feature. "
                            f"Maximum number allowed is {disable_on_date}"
                          ), 'danger')
                    return render_template('user/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form)

                max_expires_after = OrganizationSettingsManager(organization).get('password.expired.after.days')
                if expires_in > max_expires_after:
                    flash((
                            "You have chosen an invalid number of months for the password expiring feature. "
                            f"Maximum number allowed is {max_expires_after}"
                          ), 'danger')
                    return render_template('user/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form)

            # check if the password expires before the account is automatically disabled
            expires_on = today + timedelta(days=int(expires_in))
            if auto_disable and disable_on and (expires_on > disable_on or expires_on < tomorrow):
                flash('You have chosen an invalid number of days for the password expiration.', 'danger')
                return render_template('user/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form)
            
            username = form.username.data
            new_user = User(email=form.email.data, firstname=form.firstname.data.title(),
                            lastname=form.lastname.data.title(), username=username, self_renew=self_renew,
                            is_admin=False, expires_on=expires_on, creator_id=current_user.get_id(),
                            created_on=today, organization_id=organization_id, is_active=is_active)

            if auto_disable:
                new_user.disable_on = disable_on

            db.session.add(new_user)

            # this is a new user, we check if radius contains stale attributes
            db.session.query(Radcheck).filter(Radcheck.username == username).delete()
            db.session.query(Radreply).filter(Radreply.username == username).delete()
            db.session.query(Radpostauth).filter(Radpostauth.username == username).delete()
            db.session.query(Radacct).filter(Radacct.username == username).delete()

            # chose according to registration method
            if form.registration_method.data == 'password_by_admin':
                hash_type = GlobalSettingsManager.get('hashing.algorithm')
                hash_ = make_hash(form.password1.data, hash_type)
                radcheck_record = Radcheck(username=username, attribute=hash_type, op=':=', value=hash_)
                db.session.add(radcheck_record)
            else:

                if current_user.is_contact_person():
                    max_token_expires_after = OrganizationSettingsManager(organization).get('token.expired.after.hours')
                else:
                    max_token_expires_after = GlobalSettingsManager.get('max.token.expired.after.hours')

                token_expires_on = datetime.now() + timedelta(hours=max_token_expires_after)
                new_token = Token(token=make_token(), expires_on=token_expires_on,
                                  action=ActionEnum.activate, user_id=new_user.id)
                db.session.add(new_token)
                
                send_account_activation(new_token)

            db.session.commit()

            # we clear form fields...
            for field in form:
                field.data = ""

            # ... and reset date & time related fields
            form.disable_on.data = disable_on_date
            form.expires_in.data = max_expires_after

            flash(f"User {username} has been added", 'success')

        except SQLAlchemyError as e:
            flash(str(e), 'danger')

    return render_template('user/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form)


@user.route('/admin/user/password/change/<int:uid>', methods=['POST'])
@is_admin_or_contact_person
def admin_change_password(uid):
    """
    this view is used by an admin or a contact person to unilaterally change user's password
    """

    try:
        # retrieve the user object associated to the provided uid
        this_user = db.session.query(User).get(uid)

        if not this_user:
            # TODO log
            abort(404)

        # we get a list of organization IDs which can be managed
        # by the current admin (all the organizations) or
        # by the current contact person
        # ~ org_ids = [x.id for x in current_user.managed_organizations()]

        # ~ if this_user.organization_id not in org_ids:
        if not current_user.can_manage(this_user):
            # TODO log
            abort(403)

        form = PasswordForm(request.form)
        if not form.validate():
            # if the form is not valid, we flash an error message to the current admin...
            flash("Invalid input", "danger")
            # ... we will redirect to user list later
        else:
        
            password = form.password1.data

            # when changing password we must ensure that there is ONLY one password-like check attribute
            # we remove ALL password like attributes...
            db.session.query(Radcheck).filter((Radcheck.username == this_user.username) &
                                              (Radcheck.attribute.like("%-Password")) &
                                              (Radcheck.op == ':=')).delete(synchronize_session=False)

            # retrieve the hashing algorithm and creating the Radcheck record
            hash_type = GlobalSettingsManager.get('hashing.algorithm')
            hash_ = make_hash(password, hash_type)
            radcheck_record = Radcheck(username=this_user.username, attribute=hash_type, op=':=', value=hash_)

            db.session.add(radcheck_record)

            db.session.commit()

            flash("Password changed", "success")

    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.details', uid=uid))


@user.route('/user/password', methods=['GET', 'POST'])
@is_authenticated
def change_password():
    """
    this view is used by authenticated users to update their password
    """

    # instantiate the form
    form = ChangePasswordForm()
    form.password1.flags.required = True
    form.password2.flags.required = True
    form.current_password.flags.required = True
    form.password1.validators.append(InputRequired())
    form.password2.validators.append(InputRequired())

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            # by design, MFG handles ONLY one password-like check attribute
            # but it also allows administrators to specify arbitrary check attributes.
            # For this reason, when password(s) are updated,
            # MFG AUTOMATICALLY DELETES ALL old password-like check attributes.

            # We check if the supplied "current password" is valid...
            attrs = db.session.query(Radcheck).filter((Radcheck.username == current_user.username) &
                                                      (Radcheck.attribute.like("%-Password")) &
                                                      (Radcheck.op == ':=')).all()

            # ... this means that at least one password-like check attribute
            # should match with the supplied current_password hash
            matched = False
            for attr in attrs:
                try:
                    matched = check_password_hash(form.current_password.data, attr.value, attr.attribute)
                    if matched:
                        break

                except ValueError:
                    # TODO log => attr.attribute algorithm not implemented
                    continue

            # if we have no matches, the supplied password is not valid.
            if not matched:
                flash("The specified current password is not valid.", 'danger')
            else:
                # a valid password has been found. Therefore the password(s) can be changed.
                # We ensure that current_user is not trying to reuse the same password
                reused = current_user.is_reusing_the_old_password(form.password1.data)

                if reused:
                    flash("The new password cannot be the same as the old password", 'danger')
                else:
                    # current_user has chosen a brand new password.
                    try:
                        # we try to generate the related hash
                        hash_type = GlobalSettingsManager.get('hashing.algorithm')
                        new_hash = make_hash(form.password1.data, hash_type)

                        # then we NORMALIZE password-like check attributes
                        db.session.query(Radcheck).filter((Radcheck.username == current_user.username) &
                                                          (Radcheck.attribute.like("%-Password")) &
                                                          (Radcheck.op == ':=')).delete(synchronize_session=False)

                        # and finally we create the new password-like check attribute
                        radcheck_record = Radcheck(username=current_user.username, attribute=hash_type, op=':=',
                                                   value=new_hash)
                        db.session.add(radcheck_record)

                        db.session.commit()
                        flash("Password successfully changed!", 'success')

                    except ValueError:
                        # TODO log => attr.attribute algorithm not implemented
                        pass

    for field in form:
        field.data = ""

    return render_template('user/change_password.html', conf=GlobalSettingsManager, current_user=current_user, form=form)


@user.route('/user/details', methods=['GET'])
@is_authenticated
def user_details():
    """
    this view is used by authenticated users to show their user details
    """

    return render_template('user/details.html', conf=GlobalSettingsManager, current_user=current_user, user=current_user)


@user.route('/admin/user/details/<int:uid>', methods=['GET'])
@is_admin_or_contact_person
def details(uid):
    """
    this view is used by an admin or a contact person to show user details
    """

    # retrieve the user object associated to the provided uid
    this_user = db.session.query(User).get(uid)

    if not this_user:
        # TODO log
        abort(404)

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    managed_organizations = current_user.managed_organizations()
    org_ids = [o.id for o in managed_organizations]

    if this_user.organization_id not in org_ids:
        # TODO log
        abort(403)

    # we instantiate an UserPersonInfoForm
    personinfo_form = UserPersonInfoForm()
    personinfo_form.firstname.data = this_user.firstname
    personinfo_form.lastname.data = this_user.lastname

    # we instantiate a ChangeEmailForm
    email_form = ChangeEmailForm()
    email_form.field.data = this_user.email

    # we instantiate a SelectOrganizationForm if the current_user
    # (who is an admin or a contact person) can change the organization
    # of another user, this happens when current_user manages more than 1 organization
    organization_form = None
    if not this_user.organization or len(managed_organizations) > 1:
        organization_form = SelectOrganizationForm()
        organization_form.organization.choices = [(int(o.id), o.name()) for o in managed_organizations]
        organization_form.organization.label.text = "Select the organization"
        organization_form.organization.data = str(this_user.organization_id)

    # we instantiate a PasswordForm
    password_form = None
    if current_user.is_admin_or_contact_person():
        password_form = PasswordForm()
        # passwords are required if the registration method is 'password_by_admin'
        password_form.password1.validators.append(InputRequired())
        password_form.password2.validators.append(InputRequired())
        password_form.password1.flags.required = True
        password_form.password2.flags.required = True

    # we instantiate an UidForm for toggling admin privileges,
    # if the current user is an admin and is not accessing their details page
    admin_toggle_form = None
    if current_user.is_admin and current_user.id != this_user.id:
        admin_toggle_form = UidForm()
        admin_toggle_form.uid.data = this_user.id

    # we instantiate an UidForm for toggling account status (enabled/disabled),
    # if the current user is an admin or contact person
    account_status_toggle_form = None
    if current_user.is_admin_or_contact_person() and current_user.id != this_user.id:
        account_status_toggle_form = UidForm()
        account_status_toggle_form.uid.data = this_user.id

    # TODO
    # ~ tokens = db.session.query(SignupToken).filter(SignupToken.email == this_user.email).all()
    # ~ at_least_one_token_not_expired = any([not t.is_expired() for t in tokens])
    # ~ is_active = this_user.is_active
    # ~ account_should_be_disabled = this_user.should_be_disabled()
    # ~ account_in_disabled_group = this_user.in_disabled_group()

    return render_template('user/details.html', conf=GlobalSettingsManager, current_user=current_user, user=this_user,
                           admin_toggle_form=admin_toggle_form, personinfo_form=personinfo_form, email_form=email_form,
                           organization_form=organization_form, account_status_toggle_form=account_status_toggle_form,
                           password_form=password_form)
