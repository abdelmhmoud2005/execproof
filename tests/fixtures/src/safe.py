import subprocess
import yaml


def safe_subprocess(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False)


def safe_yaml(data):
    return yaml.safe_load(data)


def literal_only():
    return subprocess.run(["ls", "-la"], shell=False)
