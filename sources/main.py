from neo4j import GraphDatabase, basic_auth
from src.common import utils
from src.Loader import loader, dashboard
from src.Database import init, relationships
import settings
import os


def main(filename):
    pwd = os.getcwd()
    path = pwd + "/uploads/" + filename.split(".")[0]

    driver = GraphDatabase.driver(settings.url, auth=basic_auth(settings.username, settings.password))
    driver.verify_connectivity()

    init.setup(driver)
    utils.extract_zipfile(pwd, filename)
    loader.data(path, driver)
    relationships.Add(driver)
    dashboard.push(driver)

