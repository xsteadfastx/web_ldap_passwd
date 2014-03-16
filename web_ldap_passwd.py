import os
import ldap
import sha
import string
from base64 import encodestring
from flask import Flask, render_template, session, redirect
from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import Required, EqualTo
from flask_bootstrap import Bootstrap


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

    try:
        l.result(ldap_auth)
    except:
        session['wrong_password'] = True

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
        ldap_passwd(form.username.data, form.current_passwd.data,
                    form.new_passwd.data)
        return redirect('/passwd')
    
    print session
    return render_template('index.html', form=form)


@app.route('/passwd')
def passwd():
    print session
    return render_template('result.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
