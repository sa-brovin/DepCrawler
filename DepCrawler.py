import subprocess
import json
import argparse
import logging
import sys
import os
import shutil
import re
from collections import defaultdict

# graph libraries
from plotly.graph_objs import *
import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import write_dot

pack_dep_node_name = "dependencies"
pack_devDep_node_name = "devDependencies"
common_repo_address = "git@gitlab.business-software.ru:kconcern/"
logger_name = "common"
logs_dir = "./logs/"
projects_dir = "projects"
diagrams_dir = "diagrams"

logger = logging.getLogger(logger_name)
projects = {}
G = nx.DiGraph()


# region Classes


class Storage:
    def __init__(self):
        """Constructor"""
        self.name = ""
        self.ver = ""
        self.new_ver = ""
        self.file = ""
        self.root_node = ""
        self.msg = ""
        self.is_fixed = True
        self.is_obsolete = False
        self.dep_projects = {}
        self.title = ""


class MsgCounterHandler(logging.StreamHandler):
    """Logging handler which keeps an internal count of messages."""

    def __init__(self, *args, **kwargs):
        super(MsgCounterHandler, self).__init__(*args, **kwargs)
        self.counts = defaultdict(lambda: defaultdict(int))
        self.msgs = defaultdict(lambda: defaultdict(lambda: []))

    def emit(self, record):
        record.count = self.counts[record.name][record.levelname]
        super(MsgCounterHandler, self).emit(record)
        self.counts[record.name][record.levelname] += 1


# endregion

# region Git utils


def get_file_from_repo(project_name, ver, file_name):
    project_path = "./{0}/{1}".format(projects_dir, project_name)
    if not ver:
        ver = "HEAD"
    else:
        project_path = "{0}_{1}".format(project_path, ver)

    if not os.path.exists(project_path):
        os.makedirs(project_path)
    file_path = "{0}/{1}".format(project_path, file_name)
    with open(file_path, 'a'):
        os.utime(file_path, None)

    cmd = "git archive --remote={0}{1}.git {2} {3}| tar -x; mv -f ./{3} {4}" \
        .format(common_repo_address, project_name, ver,  file_name, project_path)
    return subprocess.getstatusoutput(cmd)


def get_last_tag_from_remote_repo(project_name):
    output = subprocess.getoutput(
        "git ls-remote --tags {0}{1}.git| grep -o \'[^\\/]*$\' | sort -rV | head -n 1".format(
            common_repo_address, project_name))
    # logger.debug("\t{0:25s}{1:12s}".format(project_name, output))
    return output


def get_last_commit(project_name):
    return subprocess.getoutput(
        "git ls-remote " + common_repo_address + project_name + ".git | grep HEAD | awk \'{ print $1}\'")


def is_last_commit_equal_last_tag(project_name, last_commit_sha):
    tag_of_last_commit = subprocess.getoutput(
        "git ls-remote --tags {0}{1}.git | grep {2} | grep -o '[^\/]*$'".format(
            common_repo_address, project_name, last_commit_sha))
    if not tag_of_last_commit:
        return False, ""

    last_tag = get_last_tag_from_remote_repo(project_name)
    if tag_of_last_commit == last_tag:
        return True, last_tag
    else:
        return False, ""


def is_version_obsolete(project_name):
    last_commit = get_last_commit(project_name)
    is_obsolete, ver = is_last_commit_equal_last_tag(project_name, last_commit)
    return not is_obsolete, ver


# endregion

# region Json utils


def is_node_exists_in_json(json_loaded_data, node_name):
    if node_name in json_loaded_data:
        return True
    else:
        return False


def get_dependency_projects_from_repo(path_to_repo, json_path, dependency_root_node):
    current_project_deps = subprocess.getoutput("cat {0}/{1} | jq '.{2}[] | select(contains(\"git\"))'".
                                                format(path_to_repo, json_path, dependency_root_node))
    regex = "(?:/)(\w*.\w*.\w*.\w*)(?:.git#|.git)(\d*.\d*.\d*|\w*)(?:\")"

    dep_projects = {}
    matches = re.finditer(regex, current_project_deps, re.MULTILINE)
    for matchNum, match in enumerate(matches):
        matchNum = matchNum + 1
        r = Storage()
        r.name = match.group(1)
        r.ver = match.group(2)
        r.file = json_path
        r.root_node = dependency_root_node
        if not r.ver or r.ver == "master":
            r.title = r.name
            dep_projects[r.name] = r
        else:
            r.title = r.name+"_"+r.ver
            dep_projects[r.name+"_"+r.ver] = r
    return dep_projects


def set_new_dependency_version(json_path, dependency_root_node, dep_name, new_version):
    # read json
    with open(json_path) as data_file:
        data_loaded = json.load(data_file)

    # check nodes exists
    if not is_node_exists_in_json(data_loaded, dependency_root_node):
        raise Exception('Can not find node: <' + dependency_root_node + '> in json file.')

    if not is_node_exists_in_json(data_loaded[dependency_root_node], dep_name):
        raise Exception('Can not find node: <' + dep_name + '> in json file.')

    # write new version
    with open(json_path, 'w') as writer:
        # cut current dep string version
        initial_str = data_loaded[dependency_root_node][dep_name].split('#')

        if len(initial_str) > 0:
            repo_path = initial_str[0] + "#"
        else:
            raise Exception("Can not parse dependency string.")

        # set new version for dep string
        data_loaded[dependency_root_node][dep_name] = repo_path + new_version

        # save modified json
        json.dump(data_loaded, writer, indent=4)


# endregion

# region Other


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', dest='config', help='configuration JSON-file')

    parser.add_argument('--error', dest='report_level', const="error", action='store_const', default="warning",
                        help='Show only errors on diagram.')
    parser.add_argument('--warning', dest='report_level', const="warning", action='store_const', default="warning",
                        help='Show errors and warnings on diagram.')
    parser.add_argument('--info', dest='report_level', const="info", action='store_const', default="warning",
                        help='Show all on diagram.')

    parser.add_argument('--diag', dest='display_diag', const="display_diag", action='store_const', default=False,
                        help='Show diagram.')

    parser.add_argument('applications', nargs='*', help='Limit applications from config to build')
    parser.print_help()
    return parser.parse_args()


def get_config(path):
    with open(path, 'r') as data:
        return json.load(data)


def set_log_configuration():
    formatter = logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s', "%d-%m-%Y %H:%M:%S")
    logger.setLevel(logging.DEBUG)

    # Handler for writing in console and events counting
    ch = MsgCounterHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Handler for writing in file
    fh = logging.FileHandler("{0}log_debug.txt".format(logs_dir))
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Handler for writing info in file
    fhi = logging.FileHandler("{0}log_info.txt".format(logs_dir))
    fhi.setLevel(logging.INFO)
    fhi.setFormatter(formatter)
    logger.addHandler(fhi)

    # Handler for writing warnings in file
    fhw = logging.FileHandler("{0}log_warnings.txt".format(logs_dir))
    fhw.setLevel(logging.WARNING)
    fhw.setFormatter(formatter)
    logger.addHandler(fhw)

    # Handler for writing errors in file
    fhe = logging.FileHandler("{0}log_errors.txt".format(logs_dir))
    fhe.setLevel(logging.ERROR)
    fhe.setFormatter(formatter)
    logger.addHandler(fhe)


def merge_two_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

# endregion


def split_project_name_version(project_name):
    s = project_name.split('_')
    if len(s) < 2:
        return s[0], ""
    return s[0], s[1]


def get_dependency_projects(current_project_name_version):
    # for minimize string length
    ind = current_project_name_version

    # TODO: Exception handling
    res = get_file_from_repo(projects[ind].name, projects[ind].ver, "package.json")
    res = get_file_from_repo(projects[ind].name, projects[ind].ver, "bower.json")

    # logger.info("Current dependency: ")
    local_path_to_repo = "./{0}/{1}".format(projects_dir, ind)
    dep_projects = merge_two_dicts(get_dependency_projects_from_repo(local_path_to_repo,
                                                                     "package.json", pack_dep_node_name),
                                   get_dependency_projects_from_repo(local_path_to_repo,
                                                                     "package.json", pack_devDep_node_name))
    return merge_two_dicts(dep_projects, get_dependency_projects_from_repo(local_path_to_repo,
                                                                           "bower.json", pack_dep_node_name))


def add_edge(source, target, msg, color, edge_type, opt):
    if opt.report_level == "error" and edge_type == "error":
        G.add_edge(source, target, label=msg, color=color)
        return

    if opt.report_level == "warning":
        if edge_type == "error" or edge_type == "warning":
            G.add_edge(source, target, label=msg, color=color)
            return

    if opt.report_level == "info":
        G.add_edge(source, target, label=msg, color=color)


def do_good(current_project_name_version, opt):
    # for minimize string length
    ind = current_project_name_version
    logger.debug("Processing {0}".format(ind.upper()))

    projects[ind] = Storage()
    projects[ind].name, projects[ind].ver = split_project_name_version(ind)
    projects[ind].title = ind
    projects[ind].dep_projects = get_dependency_projects(ind)

    for i in projects[ind].dep_projects:
        current = projects[ind].dep_projects[i]

        if current.ver == "master" or not current.ver:
            current.msg = "!F"
            current.is_fixed = False
            add_edge(ind, current.title, current.msg, 'r', "error", opt)
        else:
            current.is_obsolete, current.new_ver = is_version_obsolete(current.name)
            if current.is_obsolete:
                current.msg = "!T"
                add_edge(ind, current.title, current.msg, 'y', "warning", opt)
            else:
                add_edge(ind, current.title, current.msg, 'b', "info", opt)

        if current.title not in projects:
            do_good(current.title, opt)

    """
    # Set new versions to package.json and bower.json without push to repo.
    logger.info("Modified dependency in project {0}".format(current_project_name.upper()))
    for i in range(0, len(projects)):
        if projects[i].new_ver != projects[i].ver:
            logger.info("{0:25s}old_ver:{1:12s}new_ver:{2:12s}{3:14s}{4:17s}".format(
                projects[i].name,  projects[i].ver, projects[i].new_ver, projects[i].file, projects[i].root_node))
            set_new_dependency_version("{0}/{1}".format(local_path_to_repo, projects[i].file),
                                       projects[i].root_node, projects[i].name, projects[i].new_ver)
    """


def main():
    # recreate logs directory
    if os.path.exists(logs_dir):
        shutil.rmtree(logs_dir)
        shutil.rmtree(projects_dir)
        shutil.rmtree(diagrams_dir)
    os.makedirs(logs_dir)
    os.makedirs(projects_dir)
    os.makedirs(diagrams_dir)

    set_log_configuration()
    options = parse_arguments()

    # Debug only
    # options.config = "./aks-dispatch.json"
    # options.config = "./night.json"

    config = get_config(options.config) if options.config else {}

    if not options.applications and not options.config:
        raise Exception("Application or configs is not defined in params")

    apps = [app for app in config['apps'] if app['name'] in options.applications] \
        if options.applications \
        else config['apps']

    for a in apps:
        do_good(a["name"].replace('_', '-'), options)

    # print report
    for p in projects:
        current = projects[p]
        for d in current.dep_projects:
            dep_cur = current.dep_projects[d]
            if not dep_cur.is_fixed:
                logger.error("{0:25s}{1:12s}{2:25s}{3:12s}{4:14s}{5:17s}{6:50s}".format(
                    current.name, current.ver, dep_cur.name, dep_cur.ver, dep_cur.file, dep_cur.root_node,
                    "Dependency is not fixed."))
            elif dep_cur.is_obsolete:
                logger.warning("{0:25s}{1:12s}{2:25s}{3:12s}{4:14s}{5:17s}{6:50s}".format(
                    current.name, current.ver, dep_cur.name, dep_cur.ver, dep_cur.file, dep_cur.root_node,
                    "Last commit is not tagged."))
            else:
                logger.debug("{0:25s}{1:12s}{2:25s}{3:12s}{4:14s}{5:17s}{6:50s}".format(
                    current.name, current.ver, dep_cur.name, dep_cur.ver, dep_cur.file, dep_cur.root_node, ""))

    # save network diagram, variant 1
    dot_path = "{0}/graphviz.dot".format(diagrams_dir)
    write_dot(G, dot_path)
    os.system('dot -Tsvg {0} -o {1}/graphviz.svg'.format(dot_path, diagrams_dir))

    # show network diagram, variant 2
    pos = nx.shell_layout(G)
    nx.draw_networkx_nodes(G, pos, nodecolor='k', node_shape='o')
    nx.draw_networkx_labels(G, pos)

    edges = G.edges()
    colors = [G[u][v]['color'] for u, v in edges]
    nx.draw_networkx_edges(G, pos, edgelist=edges, edge_color=colors)

    # show edges labels, if needed
    # edge_labels = dict([((u, v,), d['label']) for u, v, d in G.edges(data=True)])
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.axis('off')
    plt.savefig('{0}/networkx.png'.format(diagrams_dir), dpi=100)

    if options.display_diag:
        plt.show()

    err_count = logger.handlers[0].counts[logger_name]['ERROR']
    warn_count = logger.handlers[0].counts[logger_name]['WARNING']
    logger.info("Errors: {0}, Warnings: {1}\n".format(err_count, warn_count))


if __name__ == '__main__':
    main()
