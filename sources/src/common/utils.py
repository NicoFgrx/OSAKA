from zipfile import ZipFile
import subprocess


def extract_zipfile(pwd, filename):
    file = pwd + "/uploads/" + filename
    path = pwd + "/uploads"
    with ZipFile(file, 'r') as f:
        f.extractall(path)


def run(python_file):
    cmd = "python " + python_file
    subprocess.call(cmd, shell=True)
