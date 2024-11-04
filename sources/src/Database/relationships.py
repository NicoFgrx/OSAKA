import json


def LinkObjects(driver):
    nodes = []
    secrets = []
    pods = []
    services = []

    query = """
    MATCH (c:ClusterAdmins), (crb:ClusterRoleBindings) 
    WHERE crb.RoleRef_name = "cluster-admin" 
    CREATE (crb)-[m:MemberOf]->(c)
    """
    driver.execute_query(query)

    query = """
    MATCH (c:ClusterAdmins), (rb:RoleBindings) 
    WHERE rb.RoleRef_name = "cluster-admin" 
    CREATE (rb)-[m:MemberOf]->(c)
    """
    driver.execute_query(query)

    query = """
    MATCH (c:ClusterAdmins), (n:Nodes) 
    WHERE n.Type = "control-plane" OR
    n.Type = "master"
    CREATE (n)-[m:ReadKubeConfig]->(c)
    """
    driver.execute_query(query)

    query = """
    MATCH (n:Nodes) return n.Name
    """
    records = driver.execute_query(query)
    query = """
    MATCH (s:Secrets) return s.ServiceAccountName AS serviceaccountname, s.Name as name, s.Namespace as namespace, s.Type as type
    """
    secrets_records = driver.execute_query(query)

    query = """
    MATCH (p:Pods) return p.Name AS name, p.serviceAccount AS serviceaccount, p.Namespace as namespace, p.Labels as labels
    """
    pods_records = driver.execute_query(query)

    query = """
    MATCH (s:Services) 
    RETURN s.Name as name, s.Namespace as namespace, s.Selector as selector
    """
    services_records = driver.execute_query(query)

    for node in records[0]:
        nodes.append(node[0])
    for secret in secrets_records[0]:
        secrets.append(secret)
    for pod in pods_records[0]:
        pods.append(pod.data())
    for service in services_records[0]:
        services.append(service.data())

    for node in nodes:
        query = """
        MATCH (p:Pods WHERE NOT (p.Name CONTAINS 'csi'
        OR p.Name CONTAINS 'kube-proxy'
        OR p.Name CONTAINS 'coredns'
        OR p.Name CONTAINS 'gatekeeper'
        OR p.Name CONTAINS 'cloud-controller'
        OR p.Name CONTAINS 'calico'
        OR p.Name CONTAINS 'net-attach'
        OR p.Name CONTAINS 'cert-manager')
        AND (p.Privileged = True OR p.hostPaths OR p.Caps IS NOT NULL)),(n:Nodes) 
        WHERE p.nodeName = $node 
        AND n.Name = $node 
        CREATE (p)-[r:EscapeTo]->(n)
        """
        driver.execute_query(query, node=node)

        done = []
        for secret in secrets:
            if secret["name"] not in done:
                if secret["serviceaccountname"] is not None:
                    query = """
                    MATCH (p:Pods WHERE NOT (p.Name CONTAINS 'csi'
                    OR p.Name CONTAINS 'kube-proxy'
                    OR p.Name CONTAINS 'coredns'
                    OR p.Name CONTAINS 'gatekeeper'
                    OR p.Name CONTAINS 'cloud-controller'
                    OR p.Name CONTAINS 'calico'
                    OR p.Name CONTAINS 'net-attach'
                    OR p.Name CONTAINS 'cert-manager')),(n:Nodes),(s:Secrets) 
                    WHERE p.nodeName = $node AND p.serviceAccount = $secretsa AND n.Name = $node 
                    AND s.ServiceAccountName = $secretsa
                    AND s.Name = $secretname
                    AND p.Namespace = s.Namespace
                    WITH DISTINCT n,s
                    CREATE (n)-[r:Read]->(s)
                    """
                    driver.execute_query(query, node=node, secretsa=secret["serviceaccountname"], secretname=secret["name"])

            done.append(secret["name"])

    done = []
    for secret in secrets:

        query = """
        MATCH (s:Secrets),(crb:ClusterRoleBindings) 
        WHERE s.Name = $secretname 
        AND s.ServiceAccountName = $secretsa
        AND s.Namespace = $secretns
        AND crb.subject_namespace = $secretns
        AND crb.subject_name = $secretsa
        CREATE (s)-[m:MemberOf]->(crb)
        """
        driver.execute_query(query, secretname=secret["name"], secretsa=secret["serviceaccountname"], secretns=secret["namespace"])

        if secret["name"] not in done:
            query = """
            MATCH (s:Secrets),(rb:RoleBindings) 
            WHERE s.Name = $secretname 
            AND s.ServiceAccountName = $secretsa 
            AND rb.subject_name = $secretsa
            AND s.Namespace = rb.namespace
            CREATE (s)-[m:MemberOf]->(rb)
            """
            driver.execute_query(query, secretsa=secret["serviceaccountname"], secretname=secret["name"])

            query = """
            MATCH (s:Secrets),(rb:RoleBindings WHERE(rb.subject_name CONTAINS 'system:serviceaccounts')) 
            WHERE s.Name = $secretname
            AND s.ServiceAccountName = "default"
            AND s.Namespace = rb.namespace
            CREATE (s)-[m:MemberOf]->(rb)
            """
            driver.execute_query(query, secretname=secret["name"])

            query = """
            MATCH (p:Pods WHERE NOT (p.Name CONTAINS 'csi'
            OR p.Name CONTAINS 'kube-proxy'
            OR p.Name CONTAINS 'coredns'
            OR p.Name CONTAINS 'gatekeeper'
            OR p.Name CONTAINS 'cloud-controller'
            OR p.Name CONTAINS 'calico'
            OR p.Name CONTAINS 'net-attach'
            OR p.Name CONTAINS 'cert-manager')),(s:Secrets) 
            WHERE p.serviceAccount = $secretsa
            AND s.ServiceAccountName = $secretsa
            AND s.Name = $secretname
            AND p.Namespace = s.Namespace
            CREATE (p)-[a:AccessTo]->(s)
            """
            driver.execute_query(query, secretsa=secret["serviceaccountname"], secretname=secret["name"])
        done.append(secret["name"])

    for pod in pods:
        secrets_match = []
        if type(pod["labels"]) != type(dict()):
            pod["labels"] = json.loads(pod["labels"])
        for secret in secrets:
            if secret["type"] == "kubernetes.io/service-account-token":
                if pod["serviceaccount"] == secret["serviceaccountname"]:
                    secrets_match.append(secret)

        if not secrets_match:
            query = """
            MATCH (p:Pods WHERE NOT (p.Name CONTAINS 'csi'
            OR p.Name CONTAINS 'kube-proxy'
            OR p.Name CONTAINS 'coredns'
            OR p.Name CONTAINS 'gatekeeper'
            OR p.Name CONTAINS 'cloud-controller'
            OR p.Name CONTAINS 'calico'
            OR p.Name CONTAINS 'net-attach'
            OR p.Name CONTAINS 'cert-manager')),(crb:ClusterRoleBindings) 
            WHERE p.Name = $podname
            AND p.serviceAccount = $podsa
            AND p.Namespace = $podns
            AND crb.subject_namespace = $podns
            AND crb.subject_name = $podsa
            CREATE (p)-[m:MemberOf]->(crb)
            """
            driver.execute_query(query, podname=pod["name"], podsa=pod["serviceaccount"], podns=pod["namespace"])

            query = """
            MATCH (p:Pods WHERE NOT (p.Name CONTAINS 'csi'
            OR p.Name CONTAINS 'kube-proxy'
            OR p.Name CONTAINS 'coredns'
            OR p.Name CONTAINS 'gatekeeper'
            OR p.Name CONTAINS 'cloud-controller'
            OR p.Name CONTAINS 'calico'
            OR p.Name CONTAINS 'net-attach'
            OR p.Name CONTAINS 'cert-manager')),(rb:RoleBindings) 
            WHERE p.Name = $podname
            AND p.serviceAccount = $podsa
            AND p.Namespace = $podns
            AND rb.subject_namespace = $podns
            AND rb.subject_name = $podsa
            CREATE (p)-[m:MemberOf]->(rb)
            """
            driver.execute_query(query, podname=pod["name"], podsa=pod["serviceaccount"], podns=pod["namespace"])


        for service in services:
            x = 0
            try:
                if type(service["selector"]) != type(dict()):
                    service["selector"] = json.loads(service["selector"])
                size = len(service["selector"])
                for k1 in service["selector"]:
                    for k2 in pod["labels"]:
                        if k1 == k2 and service["selector"][k1] == pod["labels"][k2]:
                            x = x + 1
                if x == size and x > 0:
                    query = """
                    MATCH (p:Pods),(s:Services) 
                    WHERE p.Name = $podname
                    AND p.Namespace = $servicens
                    AND s.Namespace = $servicens
                    AND s.Name = $servicename
                    CREATE (s)-[m:NetworkAccess]->(p)
                    """
                    driver.execute_query(query, podname=pod["name"], servicens=service["namespace"],
                                         servicename=service["name"])
            except Exception as error:
                pass


def LinkPrivilegedRbac(driver):
    rolebindings = []
    query = """
    MATCH (rb:RoleBindings)
    WHERE any(x IN rb.risky_roles WHERE x CONTAINS '/')
    RETURN rb.Name as name, rb.namespace as namespace, rb.risky_roles as risky_roles
    """
    rolebindings_records = driver.execute_query(query)
    for rb in rolebindings_records[0]:
        rolebindings.append(rb)

    ### Links Clusterrolebindings/Rolebindings to secret they can read -> serviceaccount
    for rolebinding in rolebindings:
        for role in rolebinding["risky_roles"]:
            obj = role.split("/")[1]
            if role.split("/")[0] == "READ_SECRET":
                query = """
                MATCH (s:Secrets),(rb:RoleBindings) 
                WHERE any(x IN rb.risky_roles WHERE x CONTAINS $secretname)
                AND s.Name = $secnamelower
                AND s.Namespace = $ns
                AND rb.namespace = $ns
                CREATE (rb)-[r:CanListSecrets]->(s)
                """
                driver.execute_query(query, secnamelower=obj.lower(), ns=rolebinding["namespace"],
                                     secretname=role)
            if role.split("/")[0] == "EXEC_PODS":
                query = """
                MATCH (rb:RoleBindings),(p:Pods WHERE NOT (p.Name CONTAINS 'csi'
                    OR p.Name CONTAINS 'kube-proxy'
                    OR p.Name CONTAINS 'coredns'
                    OR p.Name CONTAINS 'gatekeeper'
                    OR p.Name CONTAINS 'cloud-controller'
                    OR p.Name CONTAINS 'calico'
                    OR p.Name CONTAINS 'net-attach'
                    OR p.Name CONTAINS 'cert-manager'))
                WHERE any(x IN rb.risky_roles WHERE x CONTAINS $podname)
                AND p.Name = $podnamelower
                AND rb.namespace = $ns
                AND p.Namespace = $ns
                CREATE (rb)-[r:CanExecPod]->(p)
                """
                driver.execute_query(query, podnamelower=obj.lower(), ns=rolebinding["namespace"],
                                     podname=role)

    query = """
    MATCH (s:Secrets),(crb:ClusterRoleBindings) 
    WHERE any(x IN crb.risky_roles WHERE x IN ["LIST_ALL","ALL_SECRETS","LIST_SECRETS"])
    CREATE (crb)-[r:CanListSecrets]->(s)
    """
    driver.execute_query(query)

    query = """
    MATCH (s:Secrets),(rb:RoleBindings) 
    WHERE any(x IN rb.risky_roles WHERE x IN ["LIST_ALL","ALL_SECRETS","LIST_SECRETS"])
    AND (s.Namespace = rb.namespace)
    CREATE (rb)-[r:CanListSecrets]->(s)
    """
    driver.execute_query(query)

    ### Links Clusterrolebindings/Rolebindings to pod on which they can execute commands
    query = """
    MATCH (crb:ClusterRoleBindings),(p:Pods WHERE NOT (p.Name CONTAINS 'csi'
        OR p.Name CONTAINS 'kube-proxy'
        OR p.Name CONTAINS 'coredns'
        OR p.Name CONTAINS 'gatekeeper'
        OR p.Name CONTAINS 'cloud-controller'
        OR p.Name CONTAINS 'calico'
        OR p.Name CONTAINS 'net-attach'
        OR p.Name CONTAINS 'cert-manager'))
    WHERE "EXEC_PODS" in crb.risky_roles
    CREATE (crb)-[r:CanExecPod]->(p)
    """
    driver.execute_query(query)

    query = """
    MATCH (rb:RoleBindings),(p:Pods WHERE NOT (p.Name CONTAINS 'csi'
        OR p.Name CONTAINS 'kube-proxy'
        OR p.Name CONTAINS 'coredns'
        OR p.Name CONTAINS 'gatekeeper'
        OR p.Name CONTAINS 'cloud-controller'
        OR p.Name CONTAINS 'calico'
        OR p.Name CONTAINS 'net-attach'
        OR p.Name CONTAINS 'cert-manager'))
    WHERE "EXEC_PODS" in rb.risky_roles
    AND rb.Namespace = p.Namespace
    CREATE (rb)-[r:CanExecPod]->(p)
    """
    driver.execute_query(query)

    query = """
    MATCH (c:ClusterAdmins),(crb:ClusterRoleBindings) 
    WHERE "ALL_CLUSTERROLEBINDINGS" in crb.risky_roles 
    OR "CREATE_CLUSTERROLEBINDINGS" in crb.risky_roles
    CREATE (crb)-[r:BindClusterRole]->(c)
    """
    driver.execute_query(query)

    query = """
    MATCH (c:ClusterAdmins),(rb:RoleBindings) 
    WHERE "ALL_ROLEBINDINGS" in rb.risky_roles 
    OR "CREATE_ROLEBINDINGS" in rb.risky_roles
    CREATE (rb)-[r:BindRole]->(c)
    """
    driver.execute_query(query)

    ### Links Clusterrolebindings/Rolebindings to node on which they can create pods
    query = """
    MATCH (n:Nodes),(crb:ClusterRoleBindings) 
    WHERE "CREATE_PODS" in crb.risky_roles 
    OR "CREATE_DAEMONSETS" in crb.risky_roles 
    OR "CREATE_REPLICASETS" in crb.risky_roles
    OR "CREATE_REPLICATIONCONTROLLERS" in crb.risky_roles
    OR "CREATE_JOBS" in crb.risky_roles
    OR "CREATE_CRONJOBS" in crb.risky_roles
    OR "CREATE_STATEFULSETS" in crb.risky_roles
    OR "ALL_PODS" in crb.risky_roles
    OR "ALL_DAEMONSETS" in crb.risky_roles 
    OR "ALL_REPLICASETS" in crb.risky_roles
    OR "ALL_REPLICATIONCONTROLLERS" in crb.risky_roles
    OR "ALL_JOBS" in crb.risky_roles
    OR "ALL_CRONJOBS" in crb.risky_roles
    OR "ALL_STATEFULSETS" in crb.risky_roles
    OR "PATCH_PODS" in crb.risky_roles
    CREATE (crb)-[r:CanCreatePods]->(n)
    """
    driver.execute_query(query)

    query = """
    MATCH (n:Nodes),(rb:RoleBindings) 
    WHERE "CREATE_PODS" in rb.risky_roles 
    OR "CREATE_DAEMONSETS" in rb.risky_roles 
    OR "CREATE_REPLICASETS" in rb.risky_roles
    OR "CREATE_REPLICATIONCONTROLLERS" in rb.risky_roles
    OR "CREATE_JOBS" in rb.risky_roles
    OR "CREATE_CRONJOBS" in rb.risky_roles
    OR "CREATE_STATEFULSETS" in rb.risky_roles
    OR "ALL_PODS" in rb.risky_roles
    OR "ALL_DAEMONSETS" in rb.risky_roles 
    OR "ALL_REPLICASETS" in rb.risky_roles
    OR "ALL_REPLICATIONCONTROLLERS" in rb.risky_roles
    OR "ALL_JOBS" in rb.risky_roles
    OR "ALL_CRONJOBS" in rb.risky_roles
    OR "ALL_STATEFULSETS" in rb.risky_roles
    OR "PATCH_PODS" in rb.risky_roles
    CREATE (rb)-[r:CanCreatePods]->(n)
    """
    driver.execute_query(query)


""" DELETE DUPLICATE RELATIONSHIPS
match ()-[r]->() 
match (s)-[r]->(e) 
with s,e,type(r) as typ, tail(collect(r)) as coll 
foreach(x in coll | delete x)
"""


def Add(driver):
    LinkObjects(driver)
    LinkPrivilegedRbac(driver)


