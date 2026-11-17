import os
import pickle
import subprocess

import yaml


def ping_host(host):
    os.system("ping -c 1 " + host)


def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)


def eval_user(user_expr):
    return eval(user_expr)


def load_config(data):
    return yaml.load(data)


def load_blob(blob):
    return pickle.loads(blob)


def literal_command():
    return os.system("ls")


def safe_subprocess(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False)


def safe_yaml(data):
    return yaml.safe_load(data)
