from flask import request, redirect, url_for, g, current_app
from werkzeug.security import check_password_hash, generate_password_hash
import hmac
import hashlib
import time
import threading
import os
import sqlite3

import tools

PULL_DISABLED_MODULES = True
PULL_OLD_REPO = True
PULL_SELF = True
RESTART_ON_WWW_PULL = False
REGISTER_PULLED = True

COMMANDS = {
    "stop": True
}

ADMIN_IP = os.getenv("ADMIN_IP")
LOGS_PW = os.getenv("LOGS_PASSWORD")
GH_WEBHOOK_TOKEN = os.getenv("GH_WEBHOOK_TOKEN")

bp = tools.MyBlueprint("admin", "www_admin", host="admin.act25.com", db="log", db_routes=["admin.logs"])
tools.limiter.limit("100/hour")(bp)

def shutdown_gunicorn():
    # create a thread to return a response (so GitHub is happy) and start a 2s timer before exiting this app
    # this is supposed to be run by systemd unit which will restart it automatically
    # the [] syntax for lambda allows to have 2 statements
    threading.Thread(target=lambda: [time.sleep(2), os.system("pkill -f gunicorn")]).start()

class AccessLogItem:
    def __init__(self, address: str, real_address: str, time: int, method: str, path: str, status: int, response_length: int,  referer: str, user_agent: str):
        self.address = address
        self.real_address = real_address
        self.time = time
        self.method = method
        self.path = path
        self.status = status
        self.response_length = response_length
        self.referer = referer
        self.user_agent = user_agent

@bp.route("/")
def home():
    data = {}

    # Pseudo IPv4 config should be set to OVERWRITE
    data["ipv4"] = request.headers.get("CF-Connecting-IP")
    data["ipv6"] = request.headers.get("CF-Connecting-IPv6")

    if data["ipv6"]:
        data["ipv4_pseudo"] = True

    data["country"] = request.headers.get("CF-IPCountry")        

    with open("/sys/class/hwmon/hwmon0/temp1_input", "r") as f:
        temperature = f.read()

    data["temperature"] = float(temperature[:2])

    latest_commit_file = tools.inst("latest_commit")
    if os.path.exists(latest_commit_file):
        with open(latest_commit_file, "r") as f:
            data["latest_commit"] = f.read()
    else:
        data["latest_commit"] = "NONE"

    for key in data:
        if not data[key]:
            data[key] = "Not found"

    return bp.render("admin.html", data=data)

@bp.route("/logs", methods=["POST"])
def logs():
    password = request.form.get("password")
    
    if not check_password_hash(generate_password_hash(LOGS_PW), password):
        return redirect(url_for("admin.home"))

    log_tuples = g.cur.execute("SELECT * FROM access ORDER BY time DESC LIMIT 1000;").fetchall()
    log_objects = []
    for log_item_data in log_tuples:
        log_objects.append(AccessLogItem(*log_item_data))

    return bp.render("logs.html", logs=log_objects)

# thanks https://clement.notin.org/blog/2021/04/13/auto-deploy-python-flask-web-app-on-github-push/ 
@bp.route("/ghwebhook", methods=["POST"])
def github_webhook():
    sig_header = request.headers.get("X-Hub-Signature-256")
    payload = request.json
    repo_info = payload.get("repository")
    cas_command = payload.get("cas-command")

    run_cas_command = False
    latest_commit = None
    repo_name = None
    head_commit = None

    if repo_info:
        repo_name = repo_info.get("name")
        if repo_name:
            head_commit = payload.get("head_commit")
            if head_commit:
                latest_commit = head_commit.get("message")

    elif cas_command:
        enabled = COMMANDS.get(cas_command)
        if enabled:
            repo_name = cas_command.upper()
            run_cas_command = True

    if sig_header and repo_name:
        header_split = sig_header.split("=")
        if len(header_split) == 2:
            request_sig = header_split[1]
            correct_sig = hmac.new(GH_WEBHOOK_TOKEN.encode("utf-8"), request.data, hashlib.sha256).hexdigest()

            if hmac.compare_digest(request_sig, correct_sig):
                modules = tools.get_modules()
                if repo_name in modules:
                    if PULL_DISABLED_MODULES or modules[repo_name]:
                        tools.log(f"WEBHOOK RECEIVED: `{repo_name}` - {'enabled' if modules[repo_name] else 'disabled'}, pulling{' anyway' if not modules[repo_name] else ''}...")
                        old_dir = os.getcwd()
                        repo_path = tools.path("modules", repo_name)

                        if os.path.isdir(repo_path):
                            os.chdir(repo_path)
                            os.system("git pull")
                            os.chdir(old_dir)

                            if REGISTER_PULLED:
                                tools.register_module(current_app, bp.dir_name)

                        else:
                            tools.log("This module's repo must be cloned first!")

                    else:
                        tools.log(f"WEBHOOK RECEIVED: `{repo_name}` - disabled, not doing anything")

                elif repo_name == "www" and PULL_SELF:
                    tools.log(f"WEBHOOK RECEIVED: `www` - Pulling own repo...")
                    if head_commit:
                        modified = head_commit.get("modified")
                        if "RUN.py" in modified or "app.py" in modified or RESTART_ON_WWW_PULL:
                            tools.log(f"Doing full restart as critical files have been modified!")
                            shutdown_gunicorn()

                        else:
                            old_dir = os.getcwd()
                            os.chdir(tools.path("."))
                            os.system("git pull")
                            os.chdir(old_dir)

                    else:
                        tools.log("No head commit info found")

                elif repo_name == "flask-sites" and PULL_OLD_REPO:
                    old_repo_path = "/home/cas/code/flask-sites"
                    if os.path.isdir(old_repo_path):
                        tools.log(f"WEBHOOK RECEIVED: `{repo_name}` - pulling old repo...")
                        old_dir = os.getcwd()
                        os.chdir(old_repo_path)
                        os.system("git pull")
                        os.chdir(old_dir)

                    else:
                        tools.log(f"WEBHOOK RECEIVED: `{repo_name}` - {old_repo_path} does not exist on this machine")

                elif repo_name == "STOP" and run_cas_command:
                    tools.log("WEBHOOK RECEIVED: `STOP` - Shutting down...")
                    shutdown_gunicorn()

                if latest_commit:
                    with open(tools.inst("latest_commit"), "w") as f:
                        f.write(latest_commit)
    
    return "hello you have reached bob, the webhook"

@bp.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r