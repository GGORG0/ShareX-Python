from flask import Flask, request, send_from_directory, render_template, redirect, session, url_for, flash, jsonify, make_response
from wtforms import Form, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import json
import os
import shelve
import string
import secrets
import random
from PIL import Image
import shutil

app = Flask(__name__)

if not os.path.exists("config"):
    os.mkdir("config")
if not os.path.exists(os.path.join("config","config.json")):
    shutil.copy("config.json.example", os.path.join("config","config.json"))
with open(os.path.join("config","config.json"), "r") as f:
    config = json.load(f)
with open("version.txt", "r") as f:
    ver = f.read()
if not os.path.exists(os.path.join("config","secret_key.txt")):
    with open(os.path.join("config","secret_key.txt"), "wb") as f:
        f.write(os.urandom(16))
with open(os.path.join("config","secret_key.txt"), "rb") as f:
    app.config['SECRET_KEY'] = f.read()
if not os.path.exists(config['storage_folder']):
    os.mkdir(config['storage_folder'])

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", name=config['name'], version=ver, motd=config['motd'], error=e)

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html", name=config['name'], version=ver, motd=config['motd'], error=e)

def login_required(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            if session['logged_in'] == True:
                return func(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route("/upload", methods=['POST'])
def upload():
    users = shelve.open(os.path.join("config", "users.shelve"))
    attributes = request.form.to_dict(flat=False)
    if 'username' not in list(attributes.keys()) or 'key' not in list(attributes.keys()):
        users.close()
        return "Required value not in request attributes", 400
    elif 'image' not in list(request.files.to_dict(flat=False).keys()):
        users.close()
        return "'image' not provided", 400

    if attributes['username'][0] not in list(users.keys()):
        users.close()
        return "User not found", 401
    elif attributes['key'][0] != users[attributes['username'][0]]['key']:
        users.close()
        return "Wrong upload key", 401
    else:
        file = request.files['image']
        name, ext = os.path.splitext(file.filename)
        file.flush()
        size = os.fstat(file.fileno()).st_size
        if ext not in config['allowed_extensions']:
            users.close()
            return "Unsupported file type", 415
        elif size > 6000000:
            users.close()
            return 'File size too large', 400

        image = Image.open(file)
        data = list(image.getdata())
        file_without_exif = Image.new(image.mode, image.size)
        file_without_exif.putdata(data)

        if users[attributes['username'][0]]['random_filename']:
            filename = secrets.token_urlsafe(5) + ext
        else:
            filename = name + ext
        file_without_exif.save(os.path.join(config['storage_folder'], filename))
        user = users[attributes['username'][0]]
        user['images'].append(filename)
        users[attributes['username'][0]] = user
        users.close()
        return json.dumps({"url": url_for("get_img", name=filename, _external=True)}), 200

@app.route("/i/<name>", methods=['GET', 'DELETE'])
def get_img(name):
    if request.method == 'GET':
        return send_from_directory(config['storage_folder'], name)
    os.remove(os.path.join(config["storage_folder"], name))
    return "OK", 200

@app.route("/")
def home():
    return render_template("index.html", name=config['name'], version=ver, motd=config['motd'])

@app.route("/discord/")
def discord():
    return redirect(f"https://discord.gg/{config['discord']}")

@app.route("/favicon.ico")
def favicon():
    return send_from_directory("config", "favicon.ico")

@app.route("/dashboard/")
@login_required
def dashboard():
    users = shelve.open(os.path.join("config", "users.shelve"))
    try:
        user = users[session['username']]
    except KeyError:
        users.close()
        return redirect(url_for("logout"))
    space = sum(
        round(
            os.stat(os.path.join(config['storage_folder'], file)).st_size
            / (1024 * 1024),
            2,
        )
        for file in list(user['images'])
    )
    ret = render_template("dashboard.html", name=config['name'], version=ver, motd=config['motd'],
                           username=user['username'], img_count=len(user['images']), uid=user['uid'],
                           key=user['key'], space=space)
    users.close()
    return ret

class LoginForm(Form):
    username = TextField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])
    
class RegistrationForm(Form):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password', [validators.DataRequired()])

@app.route("/dashboard/login/", methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        if session['logged_in'] == True:
            return redirect(url_for("dashboard"))
    else:
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            users = shelve.open(os.path.join("config", "users.shelve"))
            username = form.username.data
            if username not in list(users.keys()):
                flash("Invalid username or password")
                users.close()
                return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)

            if sha256_crypt.verify(form.password.data, users[username]['password_hash']):
                session['logged_in'] = True
                session['username'] = username
                flash("Logged in successfully.")
                users.close()
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password")
                users.close()
                return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)

        return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)

@app.route("/dashboard/logout/")
@login_required
def logout():
    session.clear()
    flash("You have been successfully logged out.")
    return redirect(url_for("home"))

@app.route("/dashboard/register/", methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        if session['logged_in'] == True:
            return redirect(url_for("dashboard"))
    else:
        form = RegistrationForm(request.form)
        if request.method == 'POST' and form.validate():
            users = shelve.open(os.path.join("config", "users.shelve"))
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.encrypt((str(form.password.data)))
            if username in list(users.keys()):
                flash("This username is already taken, please choose another")
                users.close()
                return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)
            
            if not os.path.exists(os.path.join("config", "latest_uid.txt")):
                with open(os.path.join("config", "latest_uid.txt"), "w") as f:
                    f.write("-1")
            with open(os.path.join("config", "latest_uid.txt"), "r") as f:
                try:
                    latest_uid = int(f.read())
                except ValueError:
                    latest_uid = -1
            with open(os.path.join("config", "latest_uid.txt"), "w") as f:
                f.write(str(latest_uid + 1))

            users[username] = {
                "username": username,
                "email": email,
                "password_hash": password,
                "key": f"{username}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}",
                "random_filename": True,
                "uid": latest_uid + 1,
                "images": [],
            }
            session['logged_in'] = True
            session['username'] = username
            flash("Logged in successfully.")
            users.close()
            return redirect(url_for("dashboard"))

        return render_template("register.html", name=config['name'], version=ver, motd=config['motd'], form=form)

@app.route("/dashboard/sharex-config/")
@login_required
def sharex_config():
    users = shelve.open(os.path.join("config", "users.shelve"))
    user = users[session['username']]
    cfg = {
        "Version": "13.5.0",
        "Name": config['name'],
        "DestinationType": "ImageUploader",
        "RequestMethod": "POST",
        "RequestURL": url_for("upload", _external=True),
        "Body": "MultipartFormData",
        "Arguments": {
            "username": user['username'],
            "key": user['key']
        },
        "FileFormName": "image",
        "URL": "$json:url$",
        "ThumbnailURL": "$json:url$",
        "DeletionURL": "$json:url$",
        "ErrorMessage": "$response$"
    } 
    resp = make_response(jsonify(cfg))
    users.close()
    resp.headers['Content-Disposition'] = 'attachment; filename=config.sxcu'
    resp.content_type = 'text/html; charset=utf-8'

    return resp


@app.route("/dashboard/account/")
@login_required
def account():
    users = shelve.open(os.path.join("config", "users.shelve"))
    try:
        user = users[session['username']]
    except KeyError:
        users.close()
        return redirect(url_for("logout"))
    ret = render_template("account.html", name=config['name'], version=ver, motd=config['motd'],
                           username=user['username'], uid=user['uid'], email=user['email'],
                           key=user['key'])
    users.close()
    return ret

class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', [
        validators.DataRequired(),
    ])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password', [validators.DataRequired()])

@app.route("/dashboard/change-password/", methods=['GET', 'POST'])
@login_required
def change_password():
    users = shelve.open(os.path.join("config", "users.shelve"))
    try:
        user = users[session['username']]
    except KeyError:
        users.close()
        return redirect(url_for("logout"))

    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        if sha256_crypt.verify(form.old_password.data, user['password_hash']):
            password = sha256_crypt.encrypt((str(form.password.data)))
            user['password_hash'] = password
            users[session['username']] = user
            flash("Password changed successfully.")
            users.close()
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid old password")
            users.close()
            return render_template("change_password.html", name=config['name'], version=ver, motd=config['motd'], form=form, username=user['username'])

    users.close()
    return render_template("change_password.html", name=config['name'], version=ver, motd=config['motd'], form=form, username=user['username'])


@app.route("/dashboard/delete-account/")
@login_required
def delete_account():
    users = shelve.open(os.path.join("config", "users.shelve"))
    try:
        user = users[session['username']]
    except KeyError:
        users.close()
        return redirect(url_for("logout"))

    for file in list(user['images']):
        os.remove(os.path.join(config['storage_folder'], file))
    
    del users[session['username']]

    users.close()
    flash("Account deleted successfully")
    return redirect(url_for("logout"))

@app.route("/dashboard/regenerate-key/")
@login_required
def regenerate_key():
    users = shelve.open(os.path.join("config", "users.shelve"))
    try:
        user = users[session['username']]
    except KeyError:
        users.close()
        return redirect(url_for("logout"))

    user['key'] = f"{user['username']}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}"
    users[session['username']] = user

    users.close()
    flash("Key regenerated successfully, please re-download your config!")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0")
