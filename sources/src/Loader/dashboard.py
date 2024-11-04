import uuid
import datetime
import json


def push(driver):
    with open("/loader/tools/dashboard.json") as file:
        json_dict = json.load(file)

    uuid_d = str(uuid.uuid4())
    title = "Dashboard"
    version = "2.3"
    content = json.dumps(json_dict, separators=(',', ':'))
    user = "neo4j"
    date = datetime.datetime.now().isoformat("T", "milliseconds") + 'Z'

    query = """
    OPTIONAL MATCH (n:_Neodash_Dashboard{title:$title}) DELETE n WITH 1 as X LIMIT 1 CREATE (n:_Neodash_Dashboard) 
    SET n.uuid = $uuid, n.title = $title, n.version = $version, n.user = $user, n.content = $content, 
    n.date = datetime($date) RETURN $uuid as uuid
    """
    records = driver.execute_query(query, uuid=uuid_d,
                                   title=title,
                                   version=version,
                                   content=content,
                                   date=date,
                                   user=user)

    # if len(records[0]) == 0:
    #     query = """
    #     CREATE (n:_Neodash_Dashboard) SET n.uuid = $uuid, n.title = $title,
    #     n.version = $version, n.user = $user, n.content = $content, n.date = datetime($date) RETURN $uuid as uuid
    #     """
    #     driver.execute_query(query, uuid=uuid_d,
    #                          title=title,
    #                          version=version,
    #                          content=content,
    #                          date=date,
    #                          user=user)


