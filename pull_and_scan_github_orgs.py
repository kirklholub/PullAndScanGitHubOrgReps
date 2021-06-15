"""

Pulls all GitHub repositories of all Organizations belonging to a GitHub User.
Uses the environment variable GITUSERTOKEN to identify the user and obtain permissions.
Uses https communication and the GITUSERTOKEN must have SAML SSO access enabled.

Creates a series of time-stamped git repositories to satisfy NOAA's Gold Copy requirement.

Implements repository scanning using 'git secrets' as required by NOAA GitHub policy and inspired
by potential for exploits as shown at https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/.

Creates a hierarchy of files suitable for an http server.

Developed at NOAA/OAR/GSL by Kirk.L.Holub

This repository is a software product and is not official communication
of the National Oceanic and Atmospheric Administration (NOAA), or the United
States Department of Commerce (DOC).  All NOAA GitHub project code is provided
on an 'as is' basis and the user assumes responsibility for its use.  Any
claims against the Department of Commerce or Department of Commerce bureaus
stemming from the use of this GitHub project will be governed by all
applicable Federal law.  Any reference to specific commercial products,
processes, or services by service mark, trademark, manufacturer, or
otherwise, does not constitute or imply their endorsement, recommendation
or favoring by the Department of Commerce.  The Department of Commerce
seal and logo, or the seal and logo of a DOC bureau, shall not be used
in any manner to imply endorsement of any commercial product or activity
by DOC or the United States Government.
"""


import sys
import os
import os.path
import traceback

from datetime import datetime
import json
# import re
import pprint

import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def redact_token(unsafe):
    """
    redacts the GitHub authorization token if found in the unsafe input string

    :param:
        unsafe as str containing 'token TOKENVALUE' or 'https://TOKENVALUE'
    :return:
        safe as str; unsafe with the TOKENVALUE redacted; All except first and last three characters will remain on
        respective sides of -REDACTED-
    """

    safe = ''
    if 'https' in unsafe:
        strlist = unsafe.split()
        for item in strlist:
            if 'https' in item:
                url = item.split(':')
                redacted = url[0] + '://' + url[1][2:5] + "-REDACTED-" + url[1][-3:] + ':' + url[2]
                safe = safe + ' ' + redacted
            else:
                safe = safe + ' ' + item
    else:
        tokenfound = False
        strlist = unsafe.split()
        for item in strlist:
            if tokenfound:
                redacted = item[0:3] + "-REDACTED-" + item[-5:]
                safe = safe + ' ' + redacted
                tokenfound = False
            else:
                safe = safe + ' ' + item
                if 'token' in item:
                    tokenfound = True
    return safe


def send_email(thissubject, thisbody):
    fromaddr = "noreply.gsd@noaa.gov"
    toaddr = os.environ['NOTIFY'] + " <" + os.environ['NOTIFY_EMAIL'] + ">"

    email_msg = MIMEMultipart()
    email_msg['From'] = fromaddr
    email_msg['To'] = toaddr
    # seems strange to rewrite, but required for address to look good; send msg fails if [] are included
    toaddr = os.environ['NOTIFY_EMAIL']
    email_msg['Subject'] = thissubject
    email_msg.attach(MIMEText(thisbody, 'plain'))
    email_msg = email_msg.as_string()
    server = smtplib.SMTP('localhost')
    server.sendmail(fromaddr, toaddr, email_msg)


class PullAndScanGitHubOrgs(object):
    """
    Class to pull and scan all GitHub repositories associated with a GitHub personal access token (PAT)
    GitHub site to local repository directories.
    """

    def __init__(self):

        """
        Initializes class to clone and scan all GitHub Organizations associated with an access token.
        Sets instance variables, created directories for cloning and scan reports and verifies write access to them

        :param:
            None; uses ENV variables for all input
            Required:
                GitHub Oauth or personal access token must be in ENV variable PASGHUSERTOKEN
            Optional:
                Repo clone base path may be specified using ENV variable PASCLONEBASEPATH (defaults to '/var/www/ghcas')
                HTTP base path may be specified using ENV variable PASHTTPBASEPATH (defaults to '/var/www/html/ghcas')

        :return:
            None
        """

        defaulttoken = 'PASGHUSERTOKEN_not_in_ENV'
        defaulthttpserver = 'PASHTTPSERVER_not_in_ENV'
        try:
            token = os.getenv('PASGHUSERTOKEN', default=defaulttoken).strip()
            httpserver = os.getenv('PASHTTPSERVER', default=defaulthttpserver).strip()
            clonebasepath = os.getenv('PASCLONEPATH', default='/var/www/ghcas').strip()
            httpbasepath = os.getenv('PASHTTPPATH', default='/var/www/html/ghcas').strip()
            default = httpserver + '/cassetup/secrets_patterns.txt'
            secretsurl = os.getenv('PASSECRETSURL', default=default).strip()
            default = httpserver + '/cassetup/phrases.txt'
            allowedsurl = os.getenv('PASALLOWEDSURL', default=default).strip()
            default = httpserver + '/cassetup/phrases.txt'
            phrasesurl = os.getenv('PASPHRASESURL', default=default).strip()
        except OSError as ose:
            print("OSError while reading ENV variables: " + str(ose))
            sys.exit(-1)

        if token == defaulttoken:
            print("Initialization error: " + defaulttoken)
            sys.exit(-1)

        self.__token = token
        self.__clonebasepath = clonebasepath
        self.__httpbasepath = httpbasepath
        self.__secretsurl = secretsurl
        self.__allowedsurl = allowedsurl
        self.__phrasesurl = phrasesurl

        try:
            self.__orgnames = self.get_user_orgnames()

            for path in [clonebasepath, httpbasepath]:
                if not os.path.exists(path):
                    os.makedirs(path)
                self.verify_write_permission(path)

            dirs = []
            for oname in self.get_user_orgnames():
                for path in [clonebasepath, httpbasepath]:
                    dirs.append(path + '/' + str(oname))

            for d in dirs:
                for t in ['private', 'public']:
                    basedir = os.path.join(d, t)
                    # print("      checking " + basedir)
                    if not os.path.exists(basedir):
                        os.makedirs(basedir)
            # print("     all directories created")

        except IOError as ioe:
            print("IOError " + str(ioe) + " while attempting to create directories and verify write permission")
            sys.exit(-1)

    def run_cmd(self, cmd, paramlist, execute):
        """
        prints the command list if execute is False
        passes the command list to subprocess.run if execute is True

        :param:
            cmdl: a list of stings representing a command to be executed
            execute: True or False

        :return:
            status as int; 0 on success, non-zero on failure
            result as str; stdout on success or stderr on failure
        """
        cmdl = [cmd]
        for item in paramlist:
            cmdl.append(item)
        if execute:
            try:
                instance = subprocess.run(cmdl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                status = instance.returncode
                if status == int(0):
                    result = instance.stdout.decode('utf-8')
                else:
                    result = instance.stderr.decode('utf-8')
            except os.error as ose:
                status = "FAILED"
                result = "exception: " + str(ose)
        else:
            status = 'NOT Executing:'
            result = "     cmdl: " + str(cmdl)
        return status, result

    def run_ghapicmd(self, cmd, execute):
        """
        prints the command string if execute is False
        creates a GitHub API command url and invokes subprocess.run if execute is True

        :param:
            cmd: a valid GitHub api command or a GitHub url as str
            execute: True or False;
        :return:
            status as int; 0 on success, non-zero on failure
            result as json loads
        """

        url = "https://api.github.com/" + cmd

        header = "Authorization: token " + self.get_token()
        cmdl = ["/usr/bin/curl", "-H", header, url]
        status = int(-1)
        if execute:
            try:
                instance = subprocess.run(cmdl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                status = int(instance.returncode)
                if status == int(0):
                    output = json.loads(instance.stdout.decode('utf-8'))
                else:
                    raise OSError
            except OSError as spre:
                output = json.loads('[{"exception": "' + str(spre) + '"}]')
        else:
            output = json.loads('[{"cmdl": "' + str(cmdl) + '"}]')
            output = redact_token(output)
        return status, output

    def run_ghcmd(self, cmd, url, execute):
        """
        prints the command string if execute is False
        creates a GitHub API command url and invokes subprocess.run if execute is True

        :param:
            cmd: a valid GitHub api command or a GitHub url as str
            execute: True or False
        :return:
            status as int; 0 on success, non-zero otherwise
            output as str
        """

        cmdl = ["/usr/bin/git", cmd]
        if url is not None:
            auth = "https://" + self.get_token() + ':x-oauth-basic@'
            url = str(url).replace('https://', auth)
            cmdl.append(url)

        status = int(-1)
        if execute:
            try:
                instance = subprocess.run(cmdl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                status = int(instance.returncode)
                if status == int(0):
                    output = instance.stdout.decode('utf-8')
                elif status == int(1):
                    output = instance.stderr.decode('utf-8')
                else:
                    raise OSError
            except OSError as spre:
                output = spre
        else:
            output = redact_token(str(cmdl))
        return status, str(output)

    def get_token(self):
        """
        fetches the GitHub access token
        :return: the GitHub access token as str
        """
        return str(self.__token)

    def verify_write_permission(self, path):
        """
        confirms path has write permission by creating and then deleting a test file
        :param:
            path as str:
        :return:
            None
        """

        fname = os.path.join(path, 'test.txt')
        testfile = open(fname, 'w')
        testfile.write('this is a test, this is only a test.  No action is required at this time.')
        testfile.close()
        if os.path.exists(fname):
            os.remove(fname)
            print("  verified write permission for " + str(path))
        else:
            print("     error creating test file " + fname)
            sys.exit(-1)

    def get_user_orgnames(self):
        """
        :param:
            None
        :return:
            a list of GitHub Organization names as str
        """
        orgnames = []
        status, output = self.run_ghapicmd("user/orgs", True)
        if int(status) == int(0):
            for d in output:
                orgname = str(d['login'])
                if 'GSL' not in orgname:
                    orgnames.append(orgname)
        else:
            print('status: ' + str(status))
            print('output: ' + str(output))
        return orgnames

    def get_clone_basepath(self):
        """
        returns the path where cloned repos will be stored
        :return: clonebasepath as str
        """
        return str(self.__clonebasepath)

    def get_http_basepath(self):
        """
        returns the http server document path
        :return: httpbasepath as str
        """
        return str(self.__httpbasepath)

    def get_orgnames(self):
        """
        returns a list of GitHub Organization names associated with the GitHub token
        :return: orgnames as list
        """
        return self.__orgnames

    def get_allowedurl(self):
        """
        returns FQDN url to access a list of excepted 'git secrets'
        :return: allowedsurl as str
        """
        return (self.__allowedsurl)

    def get_phrasesurl(self):
        """
        returns FQDN url to access a list of phrases to be scanned for in 'git secrets' output
        :return: phrasesurl as str
        """
        return str(self.__phrasesurl)

    def get_secretsurl(self):
        """
        returns FQDN url to access a list of secrets used to configure 'git secrets'
        :return: secretsurl as str
        """
        return str(self.__secretsurl)

    def get_org_repos(self, orgname):
        """
        fetches repository names and public/private status

        :param:
            orgname as str:
        :return:
            a list dictionaries containing repo items:
             name as str
             private status as boolean
             updated_at as str in format YYYY-mm-ddTHH:MM:SSZ
             clone_url as str
             has_wiki as boolean
        """

        pagenum = int(1)
        morepages = True
        byreponame = {}
        while morepages:
            morepages = False
            cmd = "orgs/{org}/repos?page={pnum}".format(org=orgname, pnum=pagenum)
            pagenum = pagenum + int(1)
            status, output = self.run_ghapicmd(cmd, True)
            if int(status) == int(0):
                for r in output:
                    morepages = True
                    rdict = dict()
                    rname = str(r['name'])
                    try:
                        rdict['name'] = rname
                        rdict['private'] = bool(r['private'])
                        rdict['updated_at'] = str(r['updated_at'])
                        rdict['clone_url'] = str(r['clone_url'])
                        rdict['has_wiki'] = bool(r['has_wiki'])
                    except KeyError as ke:
                        print('KeyError while fetching repos: ' + str(ke))
                        sys.exit(-1)
                    byreponame[rname] = rdict
            else:
                print('status: ' + str(status))
                print('output: ' + str(output))

        rkeys = []
        for k in byreponame.keys():
            rkeys.append(str(k))
        rkeys.sort()
        orgrepos = []
        for k in rkeys:
            orgrepos.append(byreponame[k])
        return orgrepos

    def get_clonepath(self, orgname, repodict):
        reponame = str(repodict['name'])
        updated_at = str(repodict['updated_at'])
        state = 'public'
        if repodict['private']:
            state = 'private'
        clonepath = '/'.join([self.get_clone_basepath(), orgname, state, reponame, updated_at])
        return clonepath

    def clone_repo(self, orgname, repodict):
        """
        clones the repo specified in repodict in a date-stamped directory and according to its private status

        :param:
            orgname as str is the Organization name
            repodict as dict containing a repo's parameters
        :return:
            needtoclone as boolean; True if repo was cloned and False otherwise
        """

        reponame = str(repodict['name'])
        clonepath = self.get_clonepath(orgname, repodict)

        needtoclone = False
        try:
            if not os.path.exists(clonepath):
                os.makedirs(clonepath)
            os.chdir(clonepath)
            print('   cloning: ' + reponame + ' into ' + clonepath)
            if not os.path.exists(reponame):
                os.makedirs(reponame)
            os.chdir(reponame)
            needtoclone = True
        except IOError as ioe:
            print('IOerror creating clonepath ' + clonepath)

        if needtoclone:
            status, output = self.run_ghcmd('init', None, True)
            if int(status) == int(0):
                print('success initializing')

                clone_url = str(repodict['clone_url'])
                status, output = self.run_ghcmd('pull', clone_url, True)
                if int(status) == int(0):
                    print('success cloning ' + clone_url)
                else:
                    print('status: ' + str(status))
                    print('output: ' + str(output))

                # wiki may or may not exist
                if repodict['has_wiki']:
                    os.chdir(clonepath)
                    wikiname = reponame + '.wiki'
                    if not os.path.exists(wikiname):
                        os.makedirs(wikiname)
                    os.chdir(wikiname)
                    status, output = self.run_ghcmd('init', None, True)
                    if int(status) == int(0):
                        wiki_url = clone_url[:-4] + '.wiki.git'
                        status, output = self.run_ghcmd('pull', wiki_url, True)
                        if int(status) == int(0):
                            print('      success cloning ' + wiki_url)
                        elif int(status) == int(1):
                            print('      error cloning ' + wiki_url + ' -- error: ' + str(output))
                        else:
                            print('status: ' + str(status))
                            print('output: ' + str(output))
                    else:
                        print('wiki initialization failure status: ' + str(status))
                        print('output: ' + str(output))
                else:
                    print(clone_url + ' does not have a wiki')
            else:
                print('initialization failure status: ' + str(status))
                print('output: ' + str(output))
        return needtoclone

    def scanrepo(self, orgname, repodict):
        """
        Scans a local clone of a given repository using git-secrets.
        If a problem occurs, a message is printed to sys.stderr

        Arguments:
            orgname: repo's GitHub Organization name as str
            repodict : repository information dictionary with key-value pairs:
                    'name'       : (str) repository name; e.g., hello_world
                    'private'    : (bool) is this a private repository?
                    'clone_url'  : (str) HTTPS URL for this repo; e.g., https://github.com/NOAA-GSD/hello_world.git
                    'updated_at' : (str) time stamp of last repo update in format YYYY-mm-ddTHH:MM:SSZ
                    'has_wiki'   : (boolena) True if wiki is enabled for this repo; does not indicate wiki has content
        Returns:
            None:  scan report in json format will be written into a subpath within reportsbasepath
        """

        today = datetime.today().strftime('%Y-%m-%d_%H:%M:%S')
        scanreport = {'begintime': today}
        curl = '/usr/bin/curl'
        git = '/usr/bin/git'
        grep = '/usr/bin/grep'

        # Initialize the scan report
        try:
            httpbasepath = self.get_http_basepath()
            reportsbasepath = os.path.join(httpbasepath, orgname)
            secretsurl = self.get_secretsurl()
            allowedsurl = self.get_allowedurl()
            phrasesurl = self.get_phrasesurl()

            paramlist = ['-s', secretsurl]
            status, result = self.run_cmd(curl, paramlist, True)
            secrets = []
            for s in result.split('\n'):
                if len(s) > 0:
                    secrets.append(s)
            secrets.sort()

            paramlist = ['-s', allowedsurl]
            status, allowed = self.run_cmd(curl, paramlist, True)

            phrases = []
            paramlist = ['-s', phrasesurl]
            status, result = self.run_cmd(curl, paramlist, True)
            for p in result.split("\n"):
                if len(p) > 1:
                    phrases.append(p.strip())
                    # print( "phrases: " + str(phrases) )
            # sys.exit(-1)

            scanreport['httpbasepath'] = httpbasepath
            scanreport['reportspath'] = reportsbasepath
            scanreport['secretsurl'] = secretsurl
            scanreport['allowedsurl'] = allowedsurl
            scanreport['phrasesurl'] = phrasesurl
            scanreport['secrets'] = secrets
            scanreport['secrets_length'] = len(secrets)
            scanreport['allowed'] = allowed
            scanreport['phrases'] = phrases

        except OSError as ose:
            # Insure we have default secret and allowed patterns files -- even if they blank
            print("scanreport initialization failed -- OSError is " + str(ose))
            sys.exit(-1)

        # Get the info about the repo
        reponame = repodict['name']
        scanreport['name'] = reponame
        print("   scanning repo( " + str(reponame) + " )")

        private = repodict['private']
        scanreport['private'] = private

        clone_url = repodict['clone_url']
        scanreport['clone_url'] = clone_url

        # Get the local clone location for this repo
        clonepath = self.get_clonepath(orgname, repodict)

        # construct reports output paths
        state = 'public'
        if private:
            state = 'private'
        fnroot = os.path.join(reportsbasepath, state, reponame)
        if not os.path.exists(fnroot):
            os.makedirs(fnroot)
            print("     created " + fnroot)

        # Deal with this repo
        if not os.path.exists(clonepath):
            # This should not have happend!  We expected to be called only after a repo has been created
            today = datetime.today().isoformat(' ')
            print('{ts} :: could not locate cloned repository {rname} : {url}'.format(
                ts=today, rname=reponame, url=clone_url), file=sys.stderr)
            msg = '{ts} :: could not locate cloned repository {rname} : {url}'.format(ts=today,
                                                                                      rname=reponame, url=clone_url)
            scanreport['error'] = msg
            return scanreport
        elif os.path.isdir(clonepath):
            # Verify it is a git repo
            gitpath = os.path.join(clonepath, reponame)
            dotgit = os.path.join(gitpath, '.git')
            if os.path.isdir(dotgit):
                # Run a git secrets scan
                os.chdir(gitpath)
                print("     cd " + gitpath)
                needtoinstall = False

                # first verify secrets has been setup
                paramlist = ['secrets', '--list']
                status, output = self.run_cmd(git, paramlist, True)
                vc = int(0)
                if len(output) > 0:
                    today = datetime.today().isoformat(' ')
                    print('   {ts} :: secrets patterns listing:'.format(ts=today))
                    for line in output.split('\n'):
                        if len(line) > 1:
                            vc = vc + int(1)
                            print('      {line}'.format(line=line))
                scanreport['git--secrets--list'] = secrets
                scanreport['git--secrets--list--verifycount'] = vc
                if vc < 1:
                    needtoinstall = True

                if needtoinstall:
                    install = {}
                    scanreport['install--git'] = install
                    # Need to install and configure secrets
                    today = datetime.today().isoformat(' ')
                    print('     {ts} :: installing git secrets in repository {rname}'.format(
                        ts=today, rname=reponame), file=sys.stderr)
                    print('     {ts} :: output: {output}'.format(ts=today, output=output))

                    paramlist = ['secrets', '--install', '--force', clonepath]
                    status, output = self.run_cmd(git, paramlist, True)
                    today = datetime.today().isoformat(' ')
                    print('     {ts} :: install output:'.format(ts=today))
                    for line in output.split('\n'):
                        print('      {line}'.format(line=line))
                    install['git--secrets--install--force'] = len(output)

                    paramlist = ['secrets', '--register-aws']
                    status, output = self.run_cmd(git, paramlist, True)
                    today = datetime.today().isoformat(' ')
                    print('     {ts} :: registered aws:'.format(ts=today))
                    # for line in output.split('\n'):
                    #     print('      {line}'.format( line=line ))
                    install['git--secrets--install--registeraws'] = len(output)

                    numsecrets = int(0)
                    for s in secrets:
                        paramlist = ['secrets', '--add', s]
                        numsecrets = numsecrets + int(1)
                        status, output = self.run_cmd(git, paramlist, True)
                        today = datetime.today().isoformat(' ')
                        # print('     {ts} :: add {s}:'.format( ts=timestamp, s=s ))
                        # for line in output.split('\n'):
                        #     print('      {line}'.format( line=line ))
                    print('     {ts} :: added {ns} secrets'.format(ts=today, ns=numsecrets))
                    install['git--secrets--add'] = numsecrets

                    numallowed = int(0)
                    for a in allowed.split('\n'):
                        if len(a) > 1:
                            paramlist = ['secrets', '--add', '--allowed', a]
                            numallowed = numallowed + int(1)
                            # print('     {ts} :: cmd {cmd}:'.format( ts=timestamp, cmd=cmd ))
                            status, output = self.run_cmd(git, paramlist, True)
                            today = datetime.today().isoformat(' ')
                            # print('     {ts} :: add allowed {allowed}:'.format( ts=timestamp, allowed=allowed ))
                            # for line in output.split('\n'):
                            #     print('      {line}'.format( line=line ))
                    print('     {ts} :: added {na} allowed secrets'.format(ts=today, na=numallowed))
                    install['git--secrets--add--allowed'] = numallowed

                today = datetime.today().strftime('%Y-%m-%d_%H:%M:%S')
                errfn = fnroot + "/" + today + "_" + reponame + "_scan_error.txt"
                okfn = fnroot + "/" + today + "_" + reponame + "_scan_OK.txt"

                lfn = "SCAN_LATEST.txt"
                lfn = os.path.join(fnroot, lfn)
                if os.path.exists(lfn):
                    os.remove(lfn)
                os.symlink(okfn, lfn)

                # remove any existing scan and error files
                if os.path.exists(errfn):
                    os.remove(errfn)
                if os.path.exists(okfn):
                    os.remove(okfn)

                # show that secrets are now setup
                patterns = []
                hitreport = {}
                scanreport['hitreport'] = hitreport
                paramlist = ['secrets', '--list']
                status, output = self.run_cmd(git, paramlist, True)
                today = datetime.today().isoformat(' ')
                nh = int(0)
                if output.count('\n') > 1:
                    for line in output.split('\n'):
                        # print(' {line}'.format( line=line ))
                        patterns.append(line)
                    nh = len(patterns)
                    print('     {ts} :: secrets list output: {nh}'.format(ts=today, nh=nh))
                    hitreport['secrets--list'] = nh
                else:
                    print('  {ts} :: no output from scan.'.format(ts=today))
                scanreport['git--secrets--list--verifycount--setup'] = nh

                # get this allrepos contributor list
                # contributors = self.get_contributors(repo)
                # print( "  contributors: " + str(contributors) )

                # now scan
                scanhits = int(0)
                try:
                    today = datetime.today().isoformat(' ')
                    paramlist = ['secrets', '--scan', '--recursive']
                    okfile = open(okfn, "w")
                    okfile.write('{ts} running {cmdstr}'.format(ts=today, cmdstr=str(paramlist)) + "\n")
                    status, output = self.run_cmd(git, paramlist, True)
                    if status == 0:
                        for line in output.split('\n'):
                            okfile.write(str(line) + "\n")
                        hitreport['secrets--scan--recursive'] = len(output)
                        if hitreport['secrets--scan--recursive'] != scanreport['secrets_length']:
                            hitreport['secrets--scan--recursive--error'] = True
                        else:
                            hitreport['secrets--scan--recursive--error'] = False

                        cwd = os.getcwd()
                        pc = int(1)
                        greps = {}
                        hitreport['greps'] = greps
                        for phrase in phrases:
                            # print( "  phrase (" + str(pc) + " of " + str(len(phrases)) + "): " + phrase )
                            pc = pc + int(1)
                            paramlist = ['-r', '-i', phrase, cwd]
                            cmdstr = '/usr/bin/grep -r -i "' + phrase + '" ' + cwd
                            print("     running " + cmdstr)
                            status, output = self.run_cmd(grep, paramlist, True)
                            today = datetime.today().isoformat(' ')
                            okfile.write('{name} phrase scanned for "{phrase}" at {ts}'.format(name=reponame,
                                                                                               phrase=phrase,
                                                                                               ts=today)
                                         + " -- output: \n")
                            greps[phrase] = output.count('\n')
                            if greps[phrase] > 1:
                                for line in output.split('\n'):
                                    scanhits = scanhits + int(1)
                                    print("       " + str(line))
                                    okfile.write(str(line) + "\n")
                        okfile.close()
                    else:
                        today = datetime.today().isoformat(' ')
                        if '\n' in output:
                            outfile = open(errfn, "w")
                            print('    {ts} :: scanning output:'.format(ts=today))
                            outfile.write('{name} scanning ERROR {ts}\n'.format(name=reponame, ts=today) + "\n")
                            outfile.write("patterns used:\n")
                            for p in patterns:
                                outfile.write("   " + str(p) + "\n")
                            outfile.write("\n")

                            for line in output.split('\n'):
                                print('  {line}'.format(line=line))
                                outfile.write(line + "\n")
                            outfile.close()
                        else:
                            okfile = open(okfn, "w")
                            okfile.write('{name} scanned at {ts}\n'.format(name=reponame, ts=today)
                                         + " -- no output from scan.\n")
                            okfile.close()
                            print('    {ts} :: no output from scan.'.format(ts=today))
                        msg = "output: " + output
                        scanreport['error'] = msg
                except IOError as ioe:
                    print('IOError ' + str(ioe))

                today = datetime.today().isoformat(' ')
                if scanhits > int(0):
                    print('      {ts} :: {nh} TOTAL HITS found during scan of repository {rname}\n'.format(
                        ts=today, nh=scanhits, rname=reponame))
                    scanreport['summary'] = '{ts} :: {nh} TOTAL HITS found during scan of repository {rname}\n'.format(
                        ts=today, nh=scanhits, rname=reponame)
                print('    {ts} :: completed scan of repository {rname}\n'.format(ts=today, rname=reponame))
            else:
                today = datetime.today().isoformat(' ')
                print('{ts} :: not a git repository: {dname}'.format(
                    ts=today, dname=clonepath), file=sys.stderr)
                msg = '{ts} :: not a git repository: {dname}'.format(ts=today, dname=clonepath)
                scanreport['error'] = msg
        else:
            # Not a directory
            today = datetime.today().isoformat(' ')
            print('{ts} :: not a directory: {dname}'.format(
                ts=today, dname=clonepath), file=sys.stderr)
            msg = '{ts} :: not a directory: {dname}'.format(ts=today, dname=clonepath)
            scanreport['error'] = msg

        today = datetime.today().strftime('%Y-%m-%d_%H:%M:%S')
        scanreport['endtime'] = today

        rfn = today + "_" + reponame + ".json"
        rfn = os.path.join(fnroot, rfn).strip()
        try:
            rfile = open(rfn, "w")
            rfile.write(json.dumps(scanreport))
            rfile.close()

            lfn = "LATEST.json"
            lfn = os.path.join(fnroot, lfn)
            if os.path.exists(lfn):
                os.remove(lfn)
            os.symlink(rfn, lfn)
        except IOError as ioe:
            print('IOError ' + str(ioe))

        return scanreport


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print("\n" +
              "Clones and scans all GitHub repositories associated with a GitHub access token\n" +
              "Requires ENV variable PASGHUSERTOKEN\n" +
              "   -- If the GitHub site requires SSO authentication, then token must be SAML SSO enabled\n" +
              "ENV variable PASCLONEBASEPATH is optional and defaults to /var/html/ghcas\n" +
              "ENV variable PASHTTPBASEPATH is optional and defaults to /var/html/www/ghcas\n")
        sys.exit(1)

    try:
        cloner = PullAndScanGitHubOrgs()
        reposbyorg = {}
        for orgname in cloner.get_orgnames():
            repos = cloner.get_org_repos(orgname)
            reposbyorg[str(orgname)] = repos
            app = pprint.PrettyPrinter()
            ppstr = app.pformat(repos) + "\n"
            print(str(orgname) + ": " + str(len(repos)) + "\n" + ppstr)

        on = int(1)
        norgs = len(cloner.get_orgnames())
        print("Organization: " + str(orgname) + " has " + str(len(reposbyorg[orgname])) + ' repos')
        for orgname in reposbyorg.keys():
            print("\nprocessing repos for " + orgname + " (" + str(on) + " of " + str(norgs) + ")")
            on = on + int(1)
            rn = int(1)
            nrepos = len(reposbyorg[orgname])
            for repodict in reposbyorg[orgname]:
                name = str(repodict['name'])
                print("\nprocessing " + name + " (" + str(rn) + " of " + str(nrepos) + ")")
                rn = rn + int(1)
                need_to_scan = cloner.clone_repo(orgname, repodict)
                if need_to_scan:
                    scanreport = cloner.scanrepo(orgname, repodict)
                    pp = pprint.PrettyPrinter()
                    pp.pprint(scanreport)
            # print('breaking...')
            # break

    except OSError as ose:
        print("OSError " + str(ose))
        traceback.print_exc()
        sys.exit(-1)
