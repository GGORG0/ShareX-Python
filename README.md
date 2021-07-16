# ShareX-Python
This is a ShareX uploader server written in Python Flask, also featuring a web frontend and a dashboard.
## Hosted instance
There is a 24/7, up-to-date hosted by me instance of it named SharX available over at https://sharx.tk
## Config
1. First, create a `config` direcory.
2. There is a `config.json.example` file, copy it as `config/config.json`
3. Fill out all the values in the config:
    - `allowed_extensions`
        As the name suggests, here you should put file extensions, that are allowed.
    - `motd`
        Like most other ShareX hosting services this one also contains a MOTD. It's basically like a description.
    - `storage_folder`
        This is the folder name, that will be used for storing images. Most likely you won't touch this except if you use an external drive. Then, use `/mnt/drive` or any other mountpoint or directory.

        **Note:** Don't put a trailing slash (`/`)
    - `name`
        This is your host's name. Put whatever you want in there.
    - `discord`
        This is the invite **code** for your Discord server. That means that if my invite is `https://discord.gg/abcdef`, the code will be `abcdef`
4. Add a favicon as `config/favicon.ico`
5. Install the requirements using `pip install -r requirements.txt`
6. Start the host using a WSGI server and enjoy! A startup file for *Phusion Passenger* is included by default.

