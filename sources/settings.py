import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("NEO4J_URI")
username = os.getenv("NEO4J_USER")
password = os.getenv("NEO4J_PASSWORD")
neo4j_version = os.getenv("NEO4J_VERSION")
neo4j_database = os.getenv("NEO4J_DATABASE")
