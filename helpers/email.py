# -*- coding: utf-8 -*-
#
#  helpers/email.py
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

import htmlmin
import os
from random import SystemRandom

from flask import render_template
from flask_mail import Message

from mfg import mail
from mfg.helpers.settings import GlobalSettingsManager
from mfg.helpers.utils import lowercase_filter_word


def make_sender_tuple():
    """
    from the configuration manager loads some properties to build a tuple
    that can be flask-mail can use for forming the FROM field in the form
    Name <address>
    """
    
    smtp_email = GlobalSettingsManager.get('smtp.email')
    application_shortname = GlobalSettingsManager.get('application.shortname')
    
    if not (smtp_email or application_shortname):
        # TODO log that email cannot be sent
        return
    
    if '@' not in smtp_email:
        domain_name = smtp_email
        hexdigits="0123456789abcdef"
        
        smtp_email = lowercase_filter_word(application_shortname).replace(" ", "-")
        smtp_email += "no-reply-" + ''.join(SystemRandom().choice(hexdigits) for _ in range(8))
        smtp_email += "@" + domain_name
        
    # tuple that will form Name <address> FROM field
    sender = (application_shortname + " mail agent", smtp_email)
    return sender


def send_email(token, subject, template_folder):
    # tuple that will form Name <address> FROM field
    sender = make_sender_tuple()
    if not sender:
        return
    
    # we prefix the subject with the application's name
    subject = GlobalSettingsManager.get('application.name') + " :: " + subject
    
    # we create a list with a single recipient
    user = token.user
    recipients = [(user.fullname(), user.email)]
    
    # we init the email Message object
    message = Message(subject=subject, sender=sender, recipients=recipients)
    
    body_template_path = os.path.join(template_folder, "template.txt")
    html_template_path = os.path.join(template_folder, "template.html")
    
    message.body = render_template(body_template_path, conf=GlobalSettingsManager, token=token, user=user)
    
    html_output = render_template(html_template_path, conf=GlobalSettingsManager, token=token, user=user)
    html_output = str(htmlmin.minify(html_output,
                                     remove_comments=True, remove_empty_space=True, reduce_boolean_attributes=True))
    message.html = html_output

    mail.send(message)


def send_password_reset(token):
    return send_email(token, 'password reset', 'email/password_reset')


def send_account_activation(token):
    return send_email(token, 'account activation', 'email/account_activation')
