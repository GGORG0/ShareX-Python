from typing import Text
from flask import Flask, request, send_from_directory, render_template, redirect, session, url_for, flash, jsonify, make_response, g
import re
import time
from wtforms import Form, StringField, PasswordField, validators, TextAreaField
from passlib.hash import sha256_crypt
from functools import wraps
import json
import os
import datetime
import string
import secrets
import sqlite3
import random
from PIL import Image
import shutil

app = Flask(__name__)

with open("pid.txt", "w") as f:
    f.write(str(os.getpid()))

config = {}
ver = ""

DATABASE = os.path.join("config", "data.db")


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def setup_files():
    global config
    global ver
    if not os.path.exists("config"):
        os.mkdir("config")
    if not os.path.exists(os.path.join("config", "config.json")):
        shutil.copy("config.json.example",
                    os.path.join("config", "config.json"))
    with open(os.path.join("config", "config.json"), "r") as f:
        config = json.load(f)
    with open("version.txt", "r") as f:
        ver = f.read()
    if not os.path.exists(os.path.join("config", "secret_key.txt")):
        with open(os.path.join("config", "secret_key.txt"), "wb") as f:
            f.write(os.urandom(16))
    with open(os.path.join("config", "secret_key.txt"), "rb") as f:
        app.config['SECRET_KEY'] = f.read()
    if not os.path.exists(config['storage_folder']):
        os.mkdir(config['storage_folder'])

    with app.app_context():
        db = get_db()
        db.cursor().execute(
            "CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, key TEXT NOT NULL, storage_used NUMERIC)")
        db.cursor().execute(
            "CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, name TEXT NOT NULL, ext TEXT, upload_time INTEGER NOT NULL, size_b INTEGER NOT NULL, user INTEGER NOT NULL)")
        db.cursor().execute("CREATE TABLE IF NOT EXISTS embeds (user TEXT PRIMARY KEY, color TEXT, title TEXT, desc TEXT, author_name TEXT, author_url TEXT, provider_name TEXT, provider_url TEXT)")
        db.commit()


setup_files()


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", name=config['name'], version=ver, motd=config['motd'], error=e), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html", name=config['name'], version=ver, motd=config['motd'], error=e), 500


def login_required(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            if session['logged_in'] == True:
                if 'uid' in session:
                    user = query_db('SELECT * FROM users WHERE uid = ?',
                                    [session['uid']], one=True)
                    if user is None:
                        del session['uid']
                        return redirect(url_for("logout"))

                return func(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap


@app.route("/upload", methods=['POST'])
def upload():
    attributes = request.form.to_dict(flat=False)
    if 'uid' not in list(attributes.keys()) or 'key' not in list(attributes.keys()):
        return "Required value not in request attributes", 400
    elif 'image' not in list(request.files.to_dict(flat=False).keys()):
        return "'image' not provided", 400

    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [attributes['uid'][0]], one=True)

    if user is None:
        return "User not found", 401

    if attributes['key'][0] != user['key']:
        return "Wrong upload key", 401
    file = request.files['image']
    name, ext = os.path.splitext(file.filename)
    # filename = file.filename
    file.flush()
    size = os.fstat(file.fileno()).st_size
    if ext not in config['allowed_extensions']:
        return "Unsupported file type", 415
    elif size > 6000000:
        return 'File size too large', 400

    image = Image.open(file)
    data = list(image.getdata())
    file_without_exif = Image.new(image.mode, image.size)
    file_without_exif.putdata(data)

    img_id = secrets.token_urlsafe(5)
    filename = img_id + ext
    if not os.path.exists(os.path.join(config['storage_folder'], str(user['uid']))):
        os.mkdir(os.path.join(config['storage_folder'], str(user['uid'])))
    file_without_exif.save(os.path.join(
        config['storage_folder'], str(user['uid']), filename))
    db = get_db()
    db.cursor().execute(
        "UPDATE users SET storage_used = ? WHERE uid = ?", [user['storage_used'] + size, attributes['uid'][0]])
    db.cursor().execute("INSERT INTO images VALUES (?, ?, ?, ?, ?, ?)", [
        img_id, name, ext, round(time.time()), size, attributes['uid'][0]])
    db.commit()
    return jsonify({"url": url_for("get_img", id=img_id, _external=True), "raw": url_for("img_raw", id=img_id, _external=True)}), 200


def process_embed(embed: dict, image: dict, user: dict):
    # sourcery skip: extract-method
    if embed is None:
        embed = {}
    embed = {**{'color': '', 'title': '', 'desc': '', 'author_name': '',
                'author_url': '', 'provider_name': '', 'provider_url': ''}, **embed}

    space = round(user['storage_used'] / (1024 * 1024), 2)


    images = query_db('SELECT * FROM images WHERE user = ?',
                     [user['uid']])

    replace_dict = {'$user.name$': user['username'], '$user.uid$': user['uid'], '$user.email$': user['email'],
                    '$user.img_count$': len(images), '$user.used_space$': space, '$img.name$': image['name'],
                    '$img.id$': image['id'], '$img.ext$': image['ext'], '$img.uploaded_at.timestamp$': image['upload_time'],
                    '$img.uploaded_at.utc$': datetime.datetime.utcfromtimestamp(image['upload_time']).strftime("%d.%m.%Y %H:%M"),
                    '$img.size$': str(round(image['size_b'] / 1024, 2)), '$host.name$': config['name'], '$host.motd$': config['motd']}

    for a, b in replace_dict.items():
        embed['title'] = embed['title'].replace(str(a), str(b))
        embed['desc'] = embed['desc'].replace(str(a), str(b))
        embed['author_name'] = embed['author_name'].replace(str(a), str(b))
        embed['author_url'] = embed['author_url'].replace(str(a), str(b))
        embed['provider_name'] = embed['provider_name'].replace(str(a), str(b))
        embed['provider_url'] = embed['provider_url'].replace(str(a), str(b))

    return embed


@app.route("/i/<id>", methods=['GET', 'DELETE'])
def get_img(id):
    image = query_db('SELECT * FROM images WHERE id = ?',
                     [id], one=True)
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [image['user']], one=True)
    embed = query_db('SELECT * FROM embeds WHERE user = ?',
                     [image['user']], one=True)

    if embed is None:
        embed = {}

    embed = process_embed(embed, image, user)
    embed_adv = embed['author_name'] != "" or embed['author_url'] != "" or embed['provider_name'] != "" or embed['provider_url'] != ""

    color_on = embed['color'] != ""
    title_on = embed['title'] != ""
    desc_on = embed['desc'] != ""

    return render_template(
        "image.html",
        name=config['name'],
        version=ver,
        img_name=image['name'],
        img_id=image['id'],
        img_ext=image['ext'],
        size_kb=str(round(image['size_b'] / 1024, 2)),
        size_mb=str(round(image['size_b'] / (1024 * 1024), 2)),
        uploaded_by=user['username'],
        uploaded_uid=user['uid'],
        uploaded_at=datetime.datetime.utcfromtimestamp(
            image['upload_time']
        ).strftime("%d.%m.%Y %H:%M"),
        embed_color=embed['color'],
        embed_title=embed['title'],
        embed_desc=embed['desc'],
        embed_adv=embed_adv,
        embed_color_on=color_on,
        embed_title_on=title_on,
        embed_desc_on=desc_on,
    )


@app.route("/i/raw/<id>")
def img_raw(id):
    img = query_db('SELECT * FROM images WHERE id = ?',
                   [id], one=True)
    usr = img['user']
    dir = os.path.join(config['storage_folder'], str(usr))
    filename = img['id'] + img['ext']

    return send_from_directory(dir, filename)


@app.route("/i/embed/<id>")
def get_embed(id):
    image = query_db('SELECT * FROM images WHERE id = ?',
                     [id], one=True)
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [image['user']], one=True)

    embed = query_db('SELECT * FROM embeds WHERE user = ?',
                     [image['user']], one=True)

    if embed is None:
        embed = {}

    embed = process_embed(embed, image, user)

    em_json = {
        'type': 'link',
        'version': '1.0'
    }
    if embed['author_name'] != "":
        em_json['author_name'] = embed['author_name']
    if embed['author_url'] != "":
        em_json['author_url'] = embed['author_url']
    if embed['provider_name'] != "":
        em_json['provider_name'] = embed['provider_name']
    if embed['provider_url'] != "":
        em_json['provider_url'] = embed['provider_url']

    return jsonify(em_json)


@app.route("/")
def home():
    return render_template("index.html", name=config['name'], version=ver, motd=config['motd'])


@app.route("/discord/")
def discord():
    return redirect(f"https://discord.gg/{config['discord']}")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory("config", "favicon.ico")


@app.route("/logo.png")
def logo():
    return send_from_directory("config", "logo.png")


@app.route("/dashboard/")
@login_required
def dashboard():
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)
    images = query_db('SELECT * FROM images WHERE user = ?',
                    [user['uid']])
    space = round(user['storage_used'] / (1024 * 1024), 2)
    return render_template(
        "dashboard.html",
        name=config['name'],
        version=ver,
        motd=config['motd'],
        username=user['username'],
        img_count=len(images),
        uid=user['uid'],
        key=user['key'],
        space=space,
    )


@app.route("/dashboard/embed-conf/", methods=['GET', 'POST'])
@login_required
def embed_conf():
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)
    embed = query_db('SELECT * FROM embeds WHERE user = ?',
                     [user['uid']], one=True)

    if embed is None:
        embed = {}

    embed = {**{'color': '', 'title': '', 'desc': '', 'author_name': '',
                'author_url': '', 'provider_name': '', 'provider_url': ''}, **embed}
    current = embed

    class EmbedConfigForm(Form):
        color = StringField("Color (hex code)", default=embed['color'])
        title = TextAreaField("Title", default=embed['title'])
        desc = TextAreaField("Description", default=embed['desc'])
        author_name = TextAreaField(
            "Author name", default=embed['author_name'])
        author_url = StringField("Author URL", default=embed['author_url'])
        provider_name = TextAreaField(
            "Site name", default=embed['provider_name'])
        provider_url = StringField("Site URL", default=embed['provider_url'])
    form = EmbedConfigForm(request.form)
    if request.method == 'POST' and form.validate():
        if form.color.data != "":
            regex = r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$"
            regex = re.compile(regex)
            if regex.fullmatch(form.color.data):
                embed['color'] = form.color.data
            else:
                flash("Color must be empty or a hex code!")
        else:
            embed['color'] = ""
        embed['title'] = form.title.data
        embed['desc'] = form.desc.data
        embed['author_name'] = form.author_name.data
        embed['author_url'] = form.author_url.data
        embed['provider_name'] = form.provider_name.data
        embed['provider_url'] = form.provider_url.data

        db = get_db()
        db.cursor().execute(
            "REPLACE INTO embeds VALUES(?, ?, ?, ?, ?, ?, ?, ?)", [session['uid'], embed['color'], embed['title'], embed['desc'], embed['author_name'], embed['author_url'], embed['provider_name'], embed['provider_url']])
        db.commit()

        flash("Embed preferences successfully set!")

    vars = ['$user.name$', '$user.uid$', '$user.email$', '$user.img_count$', '$user.used_space$', '$img.name$', '$img.id$',
            '$img.ext$', '$img.uploaded_at.timestamp$', '$img.uploaded_at.utc$', '$img.size$', '$host.name$', '$host.motd$']
    return render_template("embed_conf.html", name=config['name'], version=ver, motd=config['motd'], form=form,
                           username=user['username'], current=current, vars=vars)


class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])


class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=20)])
    email = StringField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password', [validators.DataRequired()])


@app.route("/dashboard/login/", methods=['GET', 'POST'])
def login():  # sourcery skip: merge-nested-ifs
    if 'logged_in' in session:
        if session['logged_in'] == True:
            return redirect(url_for("dashboard"))
    else:
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            username = form.username.data
            valid = False
            user = query_db('SELECT * FROM users WHERE username = ?',
                            [username], one=True)
            if user is None:
                valid = False
            elif sha256_crypt.verify(form.password.data, user['password_hash']):
                valid = True
            else:
                valid = False

            if valid:
                session['logged_in'] = True
                session['uid'] = user['uid']
                flash("Logged in successfully.")

                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password")

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
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.hash((str(form.password.data)))
            user = query_db('SELECT * FROM users WHERE username = ?',
                            [username], one=True)
            if user is not None:
                flash("This username is already taken, please choose another")

                return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)

            # latest_uid = int(list(users.keys())[-1])
            latest_uid = query_db("SELECT MAX(uid) FROM users", one=True)[0]
            latest_uid = 0 if latest_uid is None else int(latest_uid)
            # CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, key TEXT NOT NULL, storage_used NUMERIC)

            db = get_db()
            db.cursor().execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                                [
                                    latest_uid + 1,
                                    username,
                                    email,
                                    password,
                                    f"{username}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}",
                                    0
                                ]
                                )
            db.commit()

            session['logged_in'] = True
            session['uid'] = str(latest_uid + 1)
            flash("Logged in successfully.")

            return redirect(url_for("dashboard"))

        return render_template("register.html", name=config['name'], version=ver, motd=config['motd'], form=form)


@app.route("/dashboard/sharex-config/")
@login_required
def sharex_config():
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)
    cfg = {
        "Version": "13.5.0",
        "Name": config['name'],
        "DestinationType": "ImageUploader",
        "RequestMethod": "POST",
        "RequestURL": url_for("upload", _external=True),
        "Body": "MultipartFormData",
        "Arguments": {
            "uid": user['uid'],
            "key": user['key']
        },
        "FileFormName": "image",
        "URL": "$json:url$",
        "ThumbnailURL": "$json:raw$",
        "ErrorMessage": "$response$"
    }
    resp = make_response(jsonify(cfg))

    resp.headers['Content-Disposition'] = 'attachment; filename=config.sxcu'
    resp.content_type = 'text/html; charset=utf-8'

    return resp


@app.route("/dashboard/account/")
@login_required
def account():
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)
    return render_template(
        "account.html",
        name=config['name'],
        version=ver,
        motd=config['motd'],
        username=user['username'],
        uid=user['uid'],
        email=user['email'],
        key=user['key'],
    )


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
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)

    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        if sha256_crypt.verify(form.old_password.data, user['password_hash']):
            password = sha256_crypt.encrypt((str(form.password.data)))
            db = get_db()
            db.cursor().execute("UPDATE users SET password_hash = ? WHERE uid = ?",
                                [password, session['uid']])
            db.commit()
            flash("Password changed successfully.")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid old password")
            return render_template("change_password.html", name=config['name'], version=ver, motd=config['motd'], form=form, username=user['username'])

    return render_template("change_password.html", name=config['name'], version=ver, motd=config['motd'], form=form, username=user['username'])


@app.route("/dashboard/delete-account/")
@login_required
def delete_account():
    usr_images = query_db(
        "SELECT * FROM images WHERE user = ?", [session['uid']])

    for img in usr_images:
        file = img['id'] + img['ext']
        os.remove(os.path.join(config['storage_folder'], file))

    db = get_db()
    db.cursor().execute("DELETE FROM users WHERE uid = ?", [session['uid']])
    db.commit()

    flash("Account deleted successfully")
    return redirect(url_for("logout"))


@app.route("/dashboard/regenerate-key/")
@login_required
def regenerate_key():
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)
    db = get_db()
    db.cursor().execute("UPDATE users SET key = ? WHERE uid = ?", [
        f"{user['username']}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}", session['uid']])
    db.commit()

    flash("Key regenerated successfully, please re-download your config!")
    return redirect(url_for("dashboard"))


@app.route("/dashboard/gallery/")
@login_required
def gallery():
    imgs = query_db("SELECT * FROM images WHERE user = ?", [session['uid']])
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)

    imgs.reverse()

    return render_template(
        "gallery.html",
        name=config['name'],
        version=ver,
        motd=config['motd'],
        username=user['username'],
        imgs=imgs,
    )


@app.route("/dashboard/gallery/delete-image/<id>/")
@login_required
def delete_image(id):
    user = query_db('SELECT * FROM users WHERE uid = ?',
                    [session['uid']], one=True)

    image = query_db('SELECT * FROM images WHERE id = ?',
                     [id], one=True)

    if image is None:
        flash("Image not found!")
        return redirect(url_for("gallery"))
    if image['user'] != session['uid']:
        flash("Image not owned by user!")
        return redirect(url_for("gallery"))

    os.remove(os.path.join(config['storage_folder'], str(
        user['uid']), id + image['ext']))
    db = get_db()
    db.cursor().execute(
        "UPDATE users SET storage_used = ? WHERE uid = ?", [user['storage_used'] - image['size_b'], session['uid']])
    db.cursor().execute("DELETE FROM images WHERE id = ?", [id])
    db.commit()

    flash("Image deleted successfully")
    return redirect(url_for("gallery"))


if __name__ == "__main__":
    app.run(host="0.0.0.0")
