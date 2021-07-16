from flask import Flask, request, send_from_directory, render_template, redirect, session, url_for, flash, jsonify, make_response
import re
import time
from wtforms import Form, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import json
import os
import shelve
import datetime
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
                if 'uid' in session:
                    users = shelve.open(os.path.join("config", "users.shelve"))
                    if str(session['uid']) not in users.keys():
                        users.close()
                        del session['uid']
                        return redirect(url_for("logout"))
                    users.close()
                return func(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route("/upload", methods=['POST'])
def upload():
    users = shelve.open(os.path.join("config", "users.shelve"))
    attributes = request.form.to_dict(flat=False)
    if 'uid' not in list(attributes.keys()) or 'key' not in list(attributes.keys()):
        users.close()
        return "Required value not in request attributes", 400
    elif 'image' not in list(request.files.to_dict(flat=False).keys()):
        users.close()
        return "'image' not provided", 400

    if attributes['uid'][0] not in list(users.keys()):
        users.close()
        return "User not found", 401
    elif attributes['key'][0] != users[attributes['uid'][0]]['key']:
        users.close()
        return "Wrong upload key", 401
    else:
        user = users[attributes['uid'][0]]
        images = shelve.open(os.path.join(config['storage_folder'], 'images.shelve'))
        file = request.files['image']
        name, ext = os.path.splitext(file.filename)
        # filename = file.filename
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

        img_id = secrets.token_urlsafe(5)
        filename = img_id + ext
        if not os.path.exists(os.path.join(config['storage_folder'], str(user['uid']))):
            os.mkdir(os.path.join(config['storage_folder'], str(user['uid'])))
        file_without_exif.save(os.path.join(config['storage_folder'], str(user['uid']), filename))
        user = users[attributes['uid'][0]]
        img_data = {"name": name, "id": img_id, "ext": ext, "upload_time": round(time.time()), "size_b": size, "user": str(user['uid']),
                    "embed": user['embed']}
        user['images'].append(img_id + ext)
        user['storage_used'] += size
        users[attributes['uid'][0]] = user
        images[img_id] = img_data
        images.close()
        users.close()
        return jsonify({"url": url_for("get_img", id=img_id, _external=True), "raw": url_for("img_raw", id=img_id, _external=True)}), 200

def process_embed(embed: dict, image: dict, user: dict):
    embed = {**{'color': '', 'title': '', 'desc': '', 'author_name': '', 'author_url': '', 'provider_name': '', 'provider_url': ''}, **embed}

    space = round(user['storage_used'] / (1024 * 1024), 2)

    replace_dict = {'$user.name$': user['username'], '$user.uid$': str(user['uid']), '$user.email$': user['email'], 
                    '$user.img_count$': len(user['images']), '$user.used_space$': space, '$img.name$': image['name'],
                    '$img.id$': image['id'], '$img.ext$': image['ext'], '$img.uploaded_at.timestamp$': image['upload_time'],
                    '$img.uploaded_at.utc$': datetime.datetime.utcfromtimestamp(image['upload_time']).strftime("%d.%m.%Y %H:%M"),
                    '$img.size$': str(image['size_b'] / 1024), '$host.name$': config['name'], '$host.motd$': config['motd']}
    
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
    if request.method == 'GET':
        users = shelve.open(os.path.join("config", "users.shelve"))
        images = shelve.open(os.path.join(config['storage_folder'], 'images.shelve'))
        image = images[id]
        user = users[image['user']]
        try:
            embed = image['embed']
        except KeyError:
            embed = {}

        embed = process_embed(embed, image, user)
        embed_adv = embed['author_name'] != "" or embed['author_url'] != "" or embed['provider_name'] != "" or embed['provider_url'] != ""

        color_on = embed['color'] != ""
        title_on = embed['title'] != ""
        desc_on = embed['desc'] != ""

        ret = render_template("image.html", name=config['name'], version=ver, img_name=image['name'],
                              img_id=image['id'], img_ext=image['ext'], size_kb=str(round(image['size_b'] / 1024, 2)), size_mb=str(round(image['size_b'] / (1024 * 1024), 2)), uploaded_by=user['username'],
                              uploaded_uid=user['uid'], uploaded_at=datetime.datetime.utcfromtimestamp(image['upload_time']).strftime("%d.%m.%Y %H:%M"),
                              embed_color=embed['color'], embed_title=embed['title'], embed_desc=embed['desc'], embed_adv=embed_adv, embed_color_on=color_on, embed_title_on=title_on, embed_desc_on=desc_on)
        images.close()
        users.close()
        return ret
    else:
        os.remove(os.path.join(config["storage_folder"], id))
        return "OK", 200

@app.route("/i/raw/<id>")
def img_raw(id):
    images = shelve.open(os.path.join(config['storage_folder'], 'images.shelve'))
    img = images[id]
    usr = img['user']
    dir = os.path.join(config['storage_folder'], usr)
    filename = img['id'] + img['ext']
    images.close()
    return send_from_directory(dir, filename)

@app.route("/i/embed/<id>")
def get_embed(id):
    images = shelve.open(os.path.join(config['storage_folder'], 'images.shelve'))
    users = shelve.open(os.path.join("config", "users.shelve"))
    img = images[id]
    usr = users[img['user']]
    try:
        embed = img['embed']
    except KeyError:
        embed = {}
    
    embed = process_embed(embed, img, usr)

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

    images.close()
    users.close()
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

@app.route("/dashboard/")
@login_required
def dashboard():
    users = shelve.open(os.path.join("config", "users.shelve"))
    user = users[str(session['uid'])]
    space = round(user['storage_used'] / (1024 * 1024), 2)
    ret = render_template("dashboard.html", name=config['name'], version=ver, motd=config['motd'],
                           username=user['username'], img_count=len(user['images']), uid=user['uid'],
                           key=user['key'], space=space)
    users.close()
    return ret

class EmbedConfigForm(Form):
    color = StringField("Color (hex code)")
    title = StringField("Title")
    desc = StringField("Description")
    author_name = StringField("Author name")
    author_url = StringField("Author URL")
    provider_name = StringField("Site name")
    provider_url = StringField("Site URL")


@app.route("/dashboard/embed-conf/", methods=['GET', 'POST'])
@login_required
def embed_conf():
    users = shelve.open(os.path.join("config", "users.shelve"))
    user = users[str(session['uid'])]
    embed = user['embed']
    embed = {**{'color': '', 'title': '', 'desc': '', 'author_name': '', 'author_url': '', 'provider_name': '', 'provider_url': ''}, **embed}
    current = embed
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

        user['embed'] = embed
        users[str(session['uid'])] = user

        flash("Embed preferences successfully set!")

    users.close()
    vars = ['$user.name$', '$user.uid$', '$user.email$', '$user.img_count$', '$user.used_space$', '$img.name$', '$img.id$', '$img.ext$', '$img.uploaded_at.timestamp$', '$img.uploaded_at.utc$', '$img.size$', '$host.name$', '$host.motd$']
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
            users = shelve.open(os.path.join("config", "users.shelve"))
            username = form.username.data
            valid = False
            user = None
            for usr in users.values():
                if usr['username'] == username:
                    if sha256_crypt.verify(form.password.data, usr['password_hash']):
                        user = usr
                        valid = True
                        break

            if valid:
                session['logged_in'] = True
                session['uid'] = usr['uid']
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
            password = sha256_crypt.hash((str(form.password.data)))
            if username in list(users.keys()):
                flash("This username is already taken, please choose another")
                users.close()
                return render_template("login.html", name=config['name'], version=ver, motd=config['motd'], form=form)
            
            latest_uid = len(users) - 1

            users[str(latest_uid + 1)] = {
                "username": username,
                "email": email,
                "password_hash": password,
                "key": f"{username}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}",
                "uid": latest_uid + 1,
                "images": [],
                "embed": {},
                "storage_used": 0
            }
            session['logged_in'] = True
            session['uid'] = latest_uid + 1
            flash("Logged in successfully.")
            users.close()
            return redirect(url_for("dashboard"))

        return render_template("register.html", name=config['name'], version=ver, motd=config['motd'], form=form)

@app.route("/dashboard/sharex-config/")
@login_required
def sharex_config():
    users = shelve.open(os.path.join("config", "users.shelve"))
    user = users[str(session['uid'])]
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
    user = users[str(session['uid'])]
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
    user = users[str(session['uid'])]

    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        if sha256_crypt.verify(form.old_password.data, user['password_hash']):
            password = sha256_crypt.encrypt((str(form.password.data)))
            user['password_hash'] = password
            users[str(session['uid'])] = user
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
    user = users[str(session['uid'])]

    for file in list(user['images']):
        os.remove(os.path.join(config['storage_folder'], file))
    
    del users[str(session['uid'])]

    users.close()
    flash("Account deleted successfully")
    return redirect(url_for("logout"))

@app.route("/dashboard/regenerate-key/")
@login_required
def regenerate_key():
    users = shelve.open(os.path.join("config", "users.shelve"))
    user = users[str(session['uid'])]

    user['key'] = f"{user['username']}_{''.join(random.choice(string.ascii_letters) for _ in range(10))}"
    users[str(session['uid'])] = user

    users.close()
    flash("Key regenerated successfully, please re-download your config!")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0")
