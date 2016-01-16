#!python3
class obj: pass
GITHUB_API = 'api.github.com'
import requests
import json
import base64
import random
import sys
import traceback

class Tree:
    def __init__(self, repo_name, sha, origin, branch='master', path=None):
        self.lib = obj()
        self.lib.session = origin
        self.lib.path = path
        self.lib.sha = sha
        self.lib.repo_name = repo_name
        self.lib.branch = branch
    def get(self):
        def recurse(sha, dorecurse=True, branch='master'):
            tree = self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo_name + '/git/trees/' + sha).json()['tree']
            r = []
            for x in tree:
                if x['type'] == 'tree':
                    if dorecurse:
                        tr = Tree(self.lib.repo_name, x['sha'], self.lib.session, self.lib.branch)
                        tr.update()
                        r.append(tr)
                else:
                    r.append(File(self.lib.repo_name + ':' + branch + '/' + x['path'], self.lib.session))
            return r
        return recurse(self.lib.sha)
    def update(self):
        self.tree = self.get()
class User:
    "Represents a GitHub user"
    def __init__(self, username, origin):
        self.lib = obj()
        self.lib.session = origin
        self.lib.username = username
    def get(self):
        "Gets user metadata"
        return self.lib.session.lib.utils.request(path='/users/' + self.lib.username).json()
    def get_repositories(self):
        "Gets user repos"
        return _turn_into_repos_list(self.lib.session.lib.utils.request(path='/users/' + self.lib.username + '/repos').json(), self.lib.session)
    def get_repository(self, name):
        f = _turn_into_repos_list(self.lib.session.lib.utils.request(path='/users/' + self.lib.username + '/repos').json(), self.lib.session)
        rep = None
        for x in f:
            if x.name == name:
                rep = x
        if not rep:
            raise ValueError('Repository not found')
        return rep
    def get_followers(self):
        "Gets user followers"
        return _turn_into_users_list(self.lib.session.lib.utils.request(path='/users/' + self.lib.username + '/followers').json(), self.lib.session)
    def get_following(self):
        "Gets user followings"
        return _turn_into_users_list(self.lib.session.lib.utils.request(path='/users/' + self.lib.username + '/following').json(), self.lib.session)
    def get_orgs(self):
        "Get user orgs"
        return self.lib.session.lib.utils.request(path='/users/' + self.lib.username + '/orgs').json()
class AuthUser(User):
    "Represents a GitHub user with elevated privileges"
    def __init__(self, username, origin):
        self.lib = obj()
        self.lib.session = origin
        self.lib.username = username
    def get(self):
        "Gets auth user metadata"
        return self.lib.session.lib.utils.request(path='/user').json()
    def update(self, data):
        "Updates auth user metadata"
        d = self.get()
        dm = {}
        for x in d:
            if (x in ['name', 'blog', 'email', 'company', 'location', 'hireable', 'bio']):
                dm[x] = d[x]
        for x in data:
            dm[x] = data[x]
        return self.lib.session.lib.utils.request(path='/user', method='PATCH', payload=json.dumps(dm)).json()
    def get_repositories(self):
        "Gets auth user repos"
        return _turn_into_repos_list(self.lib.session.lib.utils.request(path='/user/repos').json(), self.lib.session, AuthRepository)
    def get_repository(self, name):
        f = _turn_into_repos_list(self.lib.session.lib.utils.request(path='/user/repos').json(), self.lib.session, AuthRepository)
        rep = None
        for x in f:
            if x.lib.name == name:
                rep = x
        if not rep:
            raise ValueError('Repository not found')
        return rep
    def get_followers(self):
        "Gets auth user followers"
        return _turn_into_users_list(self.lib.session.lib.utils.request(path='/user/followers').json(), self.lib.session)
    def get_following(self):
        "Gets auth user followings"
        return _turn_into_users_list(self.lib.session.lib.utils.request(path='/user/following').json(), self.lib.session)
    def get_orgs(self):
        "Gets auth user orgs"
        return self.lib.session.lib.utils.request(path='/user/orgs').json()
    def follow(self, user):
        "Follows a user"
        return self.lib.session.lib.utils.request(path='/user/following/' + user, method='PUT', headers={'Content-Length':0}).json()
    def unfollow(self, user):
        "Unfollows a user"
        return self.lib.session.lib.utils.request(path='/user/following/' + user, method='DELETE', headers={'Content-Length':0}).json()
class Repository:
    "Represents a GitHub repository"
    def __init__(self, name, origin):
        owner = name.rsplit('/')[0]
        name = name.rsplit('/')[1]
        self.lib = obj()
        self.lib.session = origin
        self.lib.name = name
        self.lib.repo_name = owner + '/' + name
        self.lib.owner = User(owner, origin)
    def get(self):
        "Gets repo metadata"
        return self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo_name).json()
    def get_collaboraters(self):
        "Gets repo collaboraters"
        return _turn_into_users_list(self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo_name + '/collaborators').json(), self.lib.session)
    def get_tree(self, branch='master'):
        "Gets repo file tree"
        lc = self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo_name + '/git/refs/heads/' + branch).json()['object']['url']
        sha = self.lib.session.lib.utils.request(url=lc).json()['tree']['sha']
        x = Tree(self.lib.repo_name, sha, self.lib.session, branch)
        x.update()
        return x
class AuthRepository(Repository):
    "Represents a GitHub repository with elevated privileges"
    def __init__(self, name, origin):
        owner = name.rsplit('/')[0]
        name = name.rsplit('/')[1]
        self.lib = obj()
        self.lib.session = origin
        self.lib.name = name
        self.lib.repo_name = owner + '/' + name
        self.lib.owner = User(owner, origin)
class File:
    "Represents a GitHub file, example \"Dylan5797/ScratchEdit:master/ScratchEdit.pyw\""
    def __init__(self, location, origin):
        self.lib = obj()
        self.lib.session = origin
        lcc = location.rsplit('/')
        lccb = lcc[1].rsplit(':')
        self.lib.branch = lccb[1]
        self.lib.repo = lcc[0] + '/' + lccb[0]
        del lcc[0:2]
        self.lib.path = '/'.join(lcc)
    def get(self):
        ret = base64.b64decode(self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch).json()['content'].encode()).decode()
        try:
            ret = json.loads(ret)
        except:
            pass
        return ret
    def get_meta(self):
        return self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch).json()
class AuthFile(File):
    "Represents a GitHub file with elevated privileges"
    def __init__(self, location, origin):
        self.lib = obj()
        self.lib.session = origin
        lcc = location.rsplit('/')
        lccb = lcc[1].rsplit(':')
        self.lib.branch = lccb[1]
        self.lib.repo = lcc[0] + '/' + lccb[0]
        del lcc[0:2]
        self.lib.path = '/'.join(lcc)
    def update(self, contents, message=None):
        if not message:
            message = 'Update ' + self.lib.path.rsplit('/')[-1]
        if not self.exists():
            raise NotImplementedError('File does not exist. Use AuthFile.create() instead')
        if isinstance(contents, (dict, list)):
            contents = json.dumps(contents)
        if not (type(contents) == bytes):
            contents = contents.encode()
        d = self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch).json()
        nf = self.lib.session.lib.utils.request(method='PUT', path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch, payload=json.dumps({'message':message, 'path':self.lib.path, 'sha':d['sha'], 'content':base64.b64encode(contents).decode(), 'branch':self.lib.branch}))
        return nf
    def delete(self, message=None):
        if not message:
            message = 'Delete ' + self.lib.path.rsplit('/')[-1]
        if not self.exists():
            raise NotImplementedError('File does not exist. Use AuthFile.create() instead')
        d = self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch).json()
        nf = self.lib.session.lib.utils.request(method='DELETE', path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch, payload=json.dumps({'message':message, 'path':self.lib.path, 'sha':d['sha'], 'branch':self.lib.branch}))
        return nf
    def create(self, contents, message=None):
        if not message:
            message = 'Create ' + self.lib.path.rsplit('/')[-1]
        if isinstance(contents, (dict, list)):
            contents = json.dumps(contents)
        if self.exists():
            raise NotImplementedError('File already exists')
        if not (type(contents) == bytes):
            contents = contents.encode()
        nf = self.lib.session.lib.utils.request(method='PUT', path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch, payload=json.dumps({'message':message, 'path':self.lib.path, 'content':base64.b64encode(contents).decode(), 'branch':self.lib.branch}))
        return nf
    def exists(self):
        d = self.lib.session.lib.utils.request(path='/repos/' + self.lib.repo + '/contents/' + self.lib.path + '?ref=' + self.lib.branch)
        return str(d.status_code)[0] == '2'

class GitHub:
    "Base GitHub class"
    def __init__(self, username, password):
        self.lib = obj()
        self.lib.utils = obj()
        self.lib.utils.session = requests.session()
        self.lib.utils.request = self.__base_internals_request
        self.lib.auth = obj()
        self.lib.auth.username = username
        self.lib.auth.password = password
        self.lib.auth.auth = (username, password)
        self.user = AuthUser(username, self)
    def __base_internals_request(self, **options):
        headers = {}
        method = "get"
        server = GITHUB_API
        port = ''
        if 'path' in options:
            path = options['path']
        if 'method' in options:
            method = options['method'].lower()
        if 'server' in options:
            server = options['server']
        if 'headers' in options:
            headers.update(options['headers'])
        if 'payload' in options:
            headers['Content-Length'] = len(str(options['payload']))
        if 'port' in options:
            if options['port'] == None:
                port = ''
            else:
                port = ':' + str(options['port'])
        server = 'https://' + server
        if 'url' in options:
            server = ''
            port = ''
            path = options['url']
        def execute_request():
            if 'payload' in options:
                r = getattr(self.lib.utils.session, method.lower())(server + port + path, data=options['payload'], headers=headers, auth=self.lib.auth.auth)
            else:
                r = getattr(self.lib.utils.session, method.lower())(server + port + path, headers=headers, auth=self.lib.auth.auth)
            return r
        for x in range(0, 2):
            try:
                resp = execute_request()    
            except:
                continue
            else:
                break
        return resp
    def update(self, include=None, exclude=None):
        "Updates session data. Use \"include\" and \"exclude\" to select data to update."
        trans = {'repos':['repositories', self.user.get_repositories], 'orgs':['organizations', self.user.get_orgs],
                 'followers':['followers', self.user.get_followers], 'following':['following', self.user.get_following], 'meta':['metadata', self.user.get]}
        run = []
        if (include != None) and (exclude != None):
            raise ValueError('Both include and exclude were passed')
        if include != None:
            run = []
            for x in include:
                if not (x in trans):
                    raise ValueError('Unknown data parameter: "' + x + '"')
                else:
                    run.append(trans[x])
        elif exclude != None:
            for x in trans:
                if not (x in trans):
                    raise ValueError('Unknown data parameter: "' + x + '"')
                elif not (x in exclude):
                    run.append(trans[x])
        else:
            for x in trans:
                run.append(trans[x])
        for x in run:
            setattr(self, x[0], x[1]())

def _turn_into_orgs_list(orgs):
    pass
def _turn_into_users_list(users, session, name=User):
    usrs = []
    for x in users:
        usrs.append(name(x['login'], session))
    return usrs
def _turn_into_repos_list(repos, session, name=Repository):
    reps = []
    for x in repos:
        reps.append(name(x['owner']['login'] + '/' + x['name'], session))
    return reps
def _turn_into_files_list(files):
    pass
