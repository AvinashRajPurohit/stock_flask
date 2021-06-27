from wtforms.ext.sqlalchemy.orm import model_form
from forms import *
from decorators import admin_allowed
from flask_login import login_required, login_user, current_user, logout_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
import matplotlib.pyplot as plt
from alpha_vantage.timeseries import TimeSeries
from flask import request
from flask_login import UserMixin
from datetime import timedelta
from flask import session
import random, string
import os

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "database.db"))
app.config['SQLALCHEMY_DATABASE_URI'] = database_file
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
migrate.init_app(app, db)
ALPHA_API_KEY = ' Z3LDMMZ47PE9I5ND'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))

roles_users = db.Table('roles_users',
                       db.Column('users_id', db.Integer(),
                                 db.ForeignKey('user.id')),
                       db.Column('roles_id', db.Integer(),
                                 db.ForeignKey('roles.id')))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    is_admin = db.Column(db.Boolean())
    is_active = db.Column(db.Boolean())
    roles = db.relationship('Roles', secondary=roles_users,
                            backref='user', lazy='dynamic')
    script = db.relationship('SearchedScripts', backref='scripts', lazy='dynamic')

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def admin(self):
        return self.is_admin

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<User {0}>'.format(self.username)


class Roles(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return 'Role Name => {0}'.format(self.name)


class SearchedScripts(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user.id'), nullable=False)
    script_name = db.Column(db.String(100))
    graph_plot = db.Column(db.String(100))

    def __repr__(self):
        return f"Search script is {self.script_name}"


RolesForm = model_form(User, exclude=['email', 'password', 'is_active', 'id', 'username', 'script'],
                       db_session=db.session)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def random_file(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


@app.route('/')
@login_required
def home():
    file_path = ''
    q = request.args.get('q', None)
    show_plot = False
    error = ''
    search_scripts = SearchedScripts.query.all()
    if q is not None and q != '':
        ts = TimeSeries(ALPHA_API_KEY, output_format='pandas')
        try:
            data, meta = ts.get_intraday(q, interval='1min', outputsize='full')
            plt.plot(data['4. close'][:10])
            file_path = f'static/plots/plot_{q}_{current_user.id}_{random_file(5)}.png'
            with open(os.path.join(BASE_DIR, file_path), 'w') as fp:
                plt.savefig(os.path.join(BASE_DIR, file_path))
                fp.close()
                plt.close()
            s = SearchedScripts(user_id=current_user.id, script_name=q, graph_plot=file_path)
            db.session.add(s)
            db.session.commit()
            show_plot = True
        except Exception as e:
            error = 'Stock script is not found, kindly enter right script symbol.'

    return render_template('home.html', user=current_user, show_plot=show_plot, q=q, graph=file_path, error=error, scripts=search_scripts, l=len(search_scripts))


@app.context_processor
def utility_processor():
    def return_user_name(id):
        user = User.query.get(int(id))
        return user.username
    return dict(return_user_name=return_user_name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                session.permanent = True
                login_user(user, remember=True, force=True)
                flash('You are successfully log in!', category='success')
                return redirect(url_for('home'))

        flash('Invalid Credentials!', category='danger')
        return redirect(url_for('login'))
    return render_template('login.html', form=form, user=None)


@app.route('/add/user', methods=['GET', 'POST'])
@login_required
@admin_allowed
def add_user():
    if current_user.admin():
        form = AddNewUser()
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,
                            is_admin=False)
            db.session.add(new_user)
            db.session.commit()

            flash(
                f'New User has been added successfully, kindly share these credentials with {form.username.data} and assign roles here !',
                category='success')
            return redirect(url_for('assign_roles', id=new_user.id))

        return render_template('add_user.html', form=form, user=current_user)
    else:
        flash('You are not authorized for this operation!', category='danger')
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are successfully logout!', category='info')
    return redirect(url_for('login'))


@app.route('/assign/role/<id>', methods=['GET', 'POST'])
@login_required
@admin_allowed
def assign_roles(id):
    user = User.query.get_or_404(id)
    if user is None:
        flash(f'No user found with this username {user.username}!', category='info')
        return redirect(url_for('home'))
    form = RolesForm()
    if request.method == 'GET':
        form.roles.data = user.roles
    if request.method == 'POST':
        for i in request.form.getlist('roles'):
            r = Roles.query.get_or_404(int(i))
            user.roles.append(r)
        db.session.merge(user)
        db.session.commit()
        flash(f'Roles has been successfully update of {user.username}, add another user here!', category='info')
        return redirect(url_for('add_user'))
    return render_template('assign_roles.html',user=current_user, form=form, username=user.username)


@app.route('/add/role', methods=['GET', 'POST'])
@login_required
@admin_allowed
def add_role():
    form = AddRoleForm()
    if form.validate_on_submit():
        role = Roles(name=form.role_name.data, description=form.about_role.data)
        db.session.add(role)
        db.session.commit()
        flash('New role has been successfully added!', category='success')
        return redirect(url_for('add_role'))
    return render_template('add_new_role.html', form=form, user=current_user)


@app.route('/manage/users')
@login_required
@admin_allowed
def manage_users():
    all_users = User.query.all()
    return render_template('user_management.html', users=all_users, l=len(all_users), user=current_user)


@app.route('/make/admin/<id>')
@login_required
@admin_allowed
def make_remove_admin(id):
    user = User.query.get_or_404(id)
    if user.is_admin:
        user.is_admin = False
    else:
        user.is_admin = True
    db.session.commit()
    flash(f'Admin operation success for {user.username}!', category='info')
    return redirect(url_for('manage_users'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
