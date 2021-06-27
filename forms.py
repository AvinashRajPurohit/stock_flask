from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=1, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=40)])
    remember = BooleanField('remember me')


class AddNewUser(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=60)])
    username = StringField('username', validators=[InputRequired(), Length(min=1, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=40)])


class AddRoleForm(FlaskForm):
    role_name = StringField('Role Name', validators=[InputRequired(), Length(min=1, max=200)])
    about_role = TextAreaField('About Role', validators=[InputRequired(), Length(min=1, max=1500)])


class AssignRoleForm(FlaskForm):
    roles = SelectMultipleField(u'roles', validators=[InputRequired()])