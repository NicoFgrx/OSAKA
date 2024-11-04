def setup(driver):
    query = """
    MATCH (n) DETACH DELETE n
    """
    driver.execute_query(query)

    query = """
    CREATE (c:ClusterAdmins { Name : "CLUSTER ADMINS" })
    """
    driver.execute_query(query)
