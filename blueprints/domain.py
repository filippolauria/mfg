# -*- coding: utf-8 -*-
#
#  blueprints/domain.py
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
from mfg.forms import DomainForm, UidForm
from mfg.models import Domain

from mfg.helpers.config import ConfigManager
from mfg.helpers.decorators import is_admin
from mfg.helpers.utils import flash_errors


domain = Blueprint('domain', __name__)


@domain.route('/admin/domain/list')
@is_admin
def list():
    """
    this view allows admin to list all the registered domain names
    """
    domains = db.session.query(Domain).all()

    # this form is instantiated for enabling admin to delete domain names
    form = UidForm()
    return render_template('domain/list.html', conf=ConfigManager, current_user=current_user, domains=domains,
                           form=form)


@domain.route('/admin/domain/delete', methods=['POST'])
@is_admin
def delete():
    """
    csrf_token protected path to delete a domain name
    """

    # we instantiate the simple UidForm which carries an domain id
    form = UidForm(request.form)
    if not form.validate():
        # if the form does not validate, we redirect to the domain names list
        flash("Select a domain name from the following list", 'danger')
        return redirect(url_for('domain.list'))

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        record = db.session.query(Domain).get(uid)

        # if the domain name is not valid, we redirect to the domain names list
        if not record:
            flash("Select a domain name from the following list", 'danger')
            return redirect(url_for('domain.list'))

        # otherwise we delete the selected domain name
        db.session.delete(record)
        db.session.commit()
        flash("The domain name has been successfully deleted", 'success')

    except ValueError:
        # TODO log security warning
        flash("The domain name you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('domain.list'))


@domain.route('/admin/domain/edit/<int:uid>', methods=['GET', 'POST'])
@is_admin
def edit(uid):
    """
    this view allows admin to edit a domain name
    """

    # we get the domain name object associated with uid
    obj = db.session.query(Domain).get(uid)
    # if the domain name is not valid, we redirect to the domain names list
    if not obj:
        flash("Select a domain name from the following list", 'danger')
        return redirect(url_for('domain.list'))

    # we instantiate the domain form object with the data posted by admin
    form = DomainForm(request.form)

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            # if the form validates, we edit the domain name
            try:
                obj.domain_name = form.domain_name.data.lower()
                db.session.commit()

                # then we prepare the message to be flashed back to admin
                flash(f"The domain name {form.domain_name.data} has been successfully edited", 'success')
            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # we refresh form data and domain names list
    form.domain_name.data = obj.domain_name
    domains = db.session.query(Domain).all()
    return render_template('domain/edit.html', conf=ConfigManager, current_user=current_user, form=form,
                           domains=domains)


@domain.route('/admin/domain/create', methods=['GET', 'POST'])
@is_admin
def create():
    """
    this view allows admin to create a domain name
    """

    # we instantiate the DomainForm object
    form = DomainForm(request.form)
    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            try:
                # if the form is valid, we add the new organization to the db
                domain_name = form.domain_name.data.lower()
                domain = db.session.query(Domain).filter_by(domain_name=domain_name).first()

                # we add a domain ONLY if it does not already exist
                if not domain:
                    # add the new domain to the db
                    new_domain = Domain(domain_name=domain_name)
                    db.session.add(new_domain)
                    db.session.commit()

                    # we empty the form
                    form.domain_name.data = ""

                    # then flash back the message
                    flash(f"The domain name {domain_name} has been successfully added", 'success')
                else:
                    flash(f"The domain name {domain_name} already exists", 'danger')

            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    domains = db.session.query(Domain).all()
    return render_template('domain/create.html', conf=ConfigManager, current_user=current_user, form=form,
                           domains=domains)
