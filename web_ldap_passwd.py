from base64 import encodestring
from flask import Flask, render_template, redirect, flash
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import Required, EqualTo
import ldap
import os
import sha
import string


app = Flask(__name__)
app.secret_key = os.urandom(24)
Bootstrap(app)


ldap_server = 'localhost'
ldap_base = 'ou=user,dc=ecclesianuernberg,dc=de'


def ldap_passwd(username, current_passwd, new_passwd):
    search_scope = ldap.SCOPE_SUBTREE
    retrieve_attributes = ['cn']
    search_filter = 'uid='+username

    l = ldap.open(ldap_server)

    ldap_result_id = l.search(ldap_base, search_scope, search_filter,
                              retrieve_attributes)

    full_DN = l.result(ldap_result_id)[1][0][0]

    ldap_auth = l.bind(full_DN, current_passwd, ldap.AUTH_SIMPLE)

    l.result(ldap_auth)

    sha_digest = sha.new(new_passwd).digest()
    encoded_pw = '{SHA}' + string.strip(encodestring(sha_digest))

    mod_list = ((ldap.MOD_REPLACE, 'userPassword', encoded_pw),)

    l.modify(full_DN, mod_list)


class LDAPForm(Form):
    username = TextField('User', validators=[Required()])
    current_passwd = PasswordField('Current Password', validators=[Required()])
    new_passwd = PasswordField('New Password', validators=[Required(),
                               EqualTo('confirm_passwd',
                                       message='Password must match')])
    confirm_passwd = PasswordField('Confirm Password', validators=[Required()])


@app.route('/', methods=('GET', 'POST'))
def index():
    form = LDAPForm()
    if form.validate_on_submit():
        try:
            ldap_passwd(form.username.data, form.current_passwd.data,
                        form.new_passwd.data)
            flash('Succesfully changed password', 'success')
            return redirect('/')
        except:
            flash('Failed to change password', 'danger')
            return redirect('/')

    return render_template('index.html', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
