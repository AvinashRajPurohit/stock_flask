from functools import wraps
from flask import flash, url_for
from flask_login import current_user
from werkzeug.utils import redirect


def admin_allowed(view_func):
    @wraps(view_func)
    def wrapper_func(*args, **kwargs):
        if current_user.admin():
            return view_func(*args, **kwargs)
        else:
            flash('You are not authorized for this operation!', category='danger')
            return redirect(url_for('login'))
    return wrapper_func