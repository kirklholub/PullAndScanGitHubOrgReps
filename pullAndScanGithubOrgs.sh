#!/bin/bash --login

# who to bug
NOTIFY='kirk holub'
export NOTIFY
NOTIFY_EMAIL='kirk.l.holub@noaa.gov'
export NOTIFY_EMAIL

PASGITUSERTOKEN=$GITUSERTOKEN
export PASGITUSERTOKEN

PASHTTPSERVER=https://github-adm.gsd.esrl.noaa.gov
export PASHTTPSERVER

# DEFAULT values
# PASCLONEPATH=/var/www/ghcas
# export PASCLONEPATH
# PASHTTPPATH=/var/www/html/ghcas
# export PASHTTPPATH

# Paths to git secrets and allowed patterns files
# If SECRETSURL is missing (it does not appear as an ENV var --- as opposed to being a blank file), then:
#      1) the file './secrets_patterns.txt' will be created (in each repo) and used for the scan
#      2) this file contains '*'.  So it will cause ALL files to fail

# DEFAULT values
# PASSECRETSURL=$HTTPSERVER/cassetup/secrets_patterns.txt
# export PASSECRETSURL

# PASALLOWEDSURL=$HTTPSERVER/cassetup/allowed_patterns.txt
# export PASALLOWEDSURL

# PASPHRASESURL=$HTTPSERVER/cassetup/phrases.txt
# export PASPHRASESURL

# run as group apache to have write permission for REPORTSBASEPATH
#sg apache -c '/home/holub/bin/pull_and_scan_github_orgs.py
/Users/kirk.l.holub/PycharmProjects/github_orgsync/clone_and_scan_github_orgs.py