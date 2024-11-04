# From https://github.com/cyberark/kubernetes-rbac-audit/blob/master/ExtensiveRoleCheck.py
# but modified to be more fine grained

"""
pseudo code
if resourcename:
    function check if resourcename is in serviceaccounts list
    if true:
        apply privilege + resourcename -> Dangerous
    else:
        resourcename is not a serviceaccount and give access to cert, keys or password etc... -> Not dangerous depending
        of the context -> ssh key of a node is but not implemented yet
else:
    rbac apply in whole namespace and not on resourcename -> Dangerous
"""

import logging
from src.common import default


class ExtensiveRolesChecker(object):
    def __init__(self, data, role_kind, sa):
        self._role = logging.getLogger(role_kind)
        self.data = data
        self.sa = sa
        self._results = {}
        self.generate()


    @property
    def results(self):
        return self._results


    def add_result(self, name, value):
        if not (name in self._results.keys()):
            self._results[name] = [value]
        else:
            if value not in self._results[name]:
                self._results[name].append(value)


    def generate(self):
        namespace = None
        for entity in self.data['items']:
            role_name = entity['metadata']['name']
            if entity['metadata'].get('namespace'):
                namespace = entity['metadata']['namespace']
            if entity['rules'] is not None:
                for rule in entity['rules']:
                    if not rule.get('resources', None):
                        continue
                    self.get_read_secrets(rule, role_name, self.sa, namespace)
                    self.clusteradmin_role(rule, role_name)
                    self.any_resources(rule, role_name, self.sa, namespace)
                    self.any_verb(rule, role_name, self.sa, namespace)
                    self.high_risk_roles(rule, role_name, self.sa, namespace)
                    self.role_and_rolebindings(rule, role_name, self.sa, namespace)
                    self.create_pods(rule, role_name)
                    self.pods_exec(rule, role_name, self.sa, namespace)
                    self.pods_attach(rule, role_name)


    # A ServiceAccount is dangerous if its token is stored in k8s secret, search for SA in secrets
    def get_read_secrets(self, rule, role_name, serviceaccounts, namespace):
        verbs = ['*', 'get', 'list']
        sa_list = []

        if 'secrets' in rule['resources'] and any([sign for sign in verbs if sign in rule['verbs']]):
            filtered_name = self.custom_name(role_name)
            if rule.get('resourceNames'):
                sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
                if not sa_list:
                    return
            if filtered_name:
                if sa_list:
                    for i in range(len(sa_list)):
                        self.add_result(filtered_name, f'READ_SECRET/{sa_list[i]}'.upper())
                    return
                self.add_result(filtered_name, 'LIST_SECRETS')


    # Any Any roles
    def clusteradmin_role(self, rule, role_name):
        if '*' in rule['resources'] and '*' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                self.add_result(filtered_name, 'CLUSTER_ADMIN')


    # get ANY verbs:
    def any_verb(self, rule, role_name, serviceaccounts, namespace):
        sa_list = []
        if rule.get('resourceNames'):
            sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
            if not sa_list:
                return

        found_sign = []
        resources = ['secrets', 'pods', 'deployments', 'daemonsets', 'statefulsets', 'replicationcontrollers',
                     'replicasets', 'cronjobs', 'jobs', 'roles', 'clusterroles', 'rolebindings',
                     'clusterrolebindings', 'users', 'groups']

        for sign in resources:
            if sign in rule['resources']:
                found_sign.append(sign)
        if not found_sign:
            return
        if '*' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                if sa_list:
                    for i in range(len(found_sign)):
                        for j in range(len(sa_list)):
                            self.add_result(filtered_name, f'ALL_{found_sign[i]}/{sa_list[j]}'.upper())
                    return
                for i in range(len(found_sign)):
                    self.add_result(filtered_name, f'ALL_{found_sign[i]}'.upper())


    def any_resources(self, rule, role_name, serviceaccounts, namespace):
        sa_list = []
        if rule.get('resourceNames'):
            sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
            if not sa_list:
                return
        verbs = ['delete', 'deletecollection', 'create', 'list', 'get', 'impersonate']
        found_sign = []
        for sign in verbs:
            if sign in rule['verbs']:
                found_sign.append(sign)
        if not found_sign:
            return
        if '*' in rule['resources']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                if sa_list:
                    for i in range(len(found_sign)):
                        for j in range(len(sa_list)):
                            self.add_result(filtered_name, f'{found_sign[i]}/{sa_list[j]}_ALL'.upper())
                    return
                for i in range(len(found_sign)):
                    self.add_result(filtered_name, f'{found_sign[i]}_ALL'.upper())


    def high_risk_roles(self, rule, role_name, serviceaccounts, namespace):
        sa_list = []
        if rule.get('resourceNames'):
            sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
            if not sa_list:
                return

        found_attribute = []
        found_verbs = []
        verbs = ['create', 'update', 'patch']
        resources_attributes = ['deployments', 'daemonsets', 'statefulsets', 'replicationcontrollers', 'replicasets',
                                'jobs', 'cronjobs', 'pods']

        for attribute in resources_attributes:
            if attribute in rule['resources']:
                found_attribute.append(attribute)
        if not found_attribute:
            return

        for verb in verbs:
            if verb in rule['verbs']:
                found_verbs.append(verb)
        if not found_verbs:
            return
        filtered_name = self.custom_name(role_name)
        if filtered_name:
            if sa_list:
                for i in range(len(found_attribute)):
                    for j in range(len(found_verbs)):
                        for k in range(len(sa_list)):
                            self.add_result(filtered_name, f'{found_verbs[j]}_{found_attribute[i]}/{sa_list[k]}'.upper())
                return
            for i in range(len(found_attribute)):
                for j in range(len(found_verbs)):
                    self.add_result(filtered_name, f'{found_verbs[j]}_{found_attribute[i]}'.upper())


    def role_and_rolebindings(self, rule, role_name, serviceaccounts, namespace):
        sa_list = []
        if rule.get('resourceNames'):
            sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
            if not sa_list:
                return

        resources_attributes = ['rolebindings', 'roles', 'clusterrolebindings', 'clusterroles']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not found_attribute:
            return
        if 'create' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                if sa_list:
                    for i in range(len(found_attribute)):
                        for j in range(len(sa_list)):
                            self.add_result(filtered_name, f'CREATE_{found_attribute[i]}/{sa_list[j]}'.upper())
                    return
                for i in range(len(found_attribute)):
                    self.add_result(filtered_name, f'CREATE_{found_attribute[i]}'.upper())


    def create_pods(self, rule, role_name):
        if 'pods' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                self.add_result(filtered_name, 'CREATE_PODS')


    def pods_exec(self, rule, role_name, serviceaccounts, namespace):
        sa_list = []
        if rule.get('resourceNames'):
            sa_list = self.is_rnames_sa(rule["resourceNames"], serviceaccounts, namespace)
            if not sa_list:
                return
        if 'pods/exec' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                if sa_list:
                    for i in range(len(sa_list)):
                        self.add_result(filtered_name, f'EXEC_PODS/{sa_list[i]}'.upper())
                    return
                self.add_result(filtered_name, 'EXEC_PODS')


    def pods_attach(self, rule, role_name):
        if 'pods/attach' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.custom_name(role_name)
            if filtered_name:
                self.add_result(filtered_name, 'ATTACH_PODS')


    @staticmethod
    def custom_name(name):
        if name not in default.clusterroles and name not in default.roles:
            return name


    def is_rnames_sa(self, resourcenames, serviceaccounts, namespace):
        sa_list = []
        for rname in resourcenames:
            for sa in serviceaccounts:
                if rname == sa["name"] and namespace == sa["namespace"]:
                    sa_list.append(rname)
        return sa_list


def rolechecker(clusterroles, roles, sa):
    bad_roles = []
    bad_clusterroles = []
    risky_roles = {}

    extensiveClusterRolesChecker = ExtensiveRolesChecker(clusterroles, 'ClusterRole', sa)

    for result in extensiveClusterRolesChecker.results:
        risky_roles[result] = extensiveClusterRolesChecker.results[result]
        bad_clusterroles.append(result)

    extensiveRolesChecker = ExtensiveRolesChecker(roles, 'Role', sa)

    for result in extensiveRolesChecker.results:
        if result not in bad_clusterroles:
            risky_roles[result] = extensiveRolesChecker.results[result]
            bad_roles.append(result)
    return risky_roles

