#!/usr/bin/python

###################################
# Imports
###################################
from __future__ import print_function, with_statement
import argparse
import sys
import pwd
import os
import re
import subprocess
import time
import datetime
from time import localtime, strptime

__version__ = '1.0.0'

###################################
# Useful variables for the script
###################################
# Parsing commandline arguments


def options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', dest='show_version',
                        action='store_true', help='Shows script version')

    parser.add_argument('-s', '--system-users', dest='show_system_users',
                        action='store_true', help='Show system users on the device')

    parser.add_argument('-u', '--users', dest='show_users',
                        action='store_true', help='Show users on this device')

    parser.add_argument('-a', '--all-users', dest='show_all_users', action='store_true',
                        help='Show all users on this device. This is the default option')

    parser.add_argument('-F', '--show-full', dest='show_full_output', action='store_true',
                        help='When displaying, show the full user information including GECOS and Group ID')
    return parser

# Colours for display output


class Color(object):
    RED = '\033[31m\033[1m'
    GREEN = '\033[32m\033[1m'
    YELLOW = '\033[33m\033[1m'
    BLUE = '\033[34m\033[1m'
    MAGENTA = '\033[35m\033[1m'
    CYAN = '\033[36m\033[1m'
    WHITE = '\033[37m\033[1m'
    RESET = '\033[0m'

# Configuration variables


class Config(object):
    # System files
    DEFS_FILE = '/etc/login.defs'
    GROUP_FILE = '/etc/group'
    PASSWD_FILE = '/etc/passwd'
    SUDO_FILE = '/etc/sudoers'
    WTMP_FILE = '/var/log/wtmp'

    # Headers for table output
    HEADER_STANDARD = ['ID', 'User', 'Home', 'Shell', 'Sudo', 'Last Login']
    HEADER_FULL = ['ID', 'User', 'Group ID', 'GECOS',
                   'Home', 'Shell', 'Sudo', 'Last Login']

    # Other configurations
    LAST_CMD = 'last -w -i -f '

# Used for storing runtime data


class Users(object):
    # Set some sane defaults in case they are not defined (Ubuntu)
    UID_MIN = 1000
    UID_MAX = 60000
    SYS_UID_MIN = 0
    SYS_UID_MAX = 999

    SUDO_CONTENT = None
    GROUP_CONTENT = None
    USERS = None
    LOGINS = []

###################################
# Non-Display functions for the script
###################################
# Get all of the users and initalize all the required variables and data for the script


def init_variables():
    # First test we can open all the required files, exit if not
    # Check access to passwd
    try:
        open(Config.PASSWD_FILE, 'r')
    except IOError:
        sys.exit('Unable to open ' + Config.PASSWD_FILE)

    # Check access to groups
    try:
        GROUP_CONTENT = open(Config.GROUP_FILE, 'r')
        Users.GROUP_CONTENT = GROUP_CONTENT.readlines()
    except IOError:
        sys.exit('Unable to open ' + Config.GROUP_FILE)

    # Get values from defs
    try:
        with open(Config.DEFS_FILE, 'r') as f:
            lines = list(line for line in (l.strip() for l in f) if line)
    except IOError:
        sys.exit('Unable to open ' + Config.DEFS_FILE)

    for l in lines:
        fields = l.strip().split()
        if fields[0] == "UID_MIN":
            Users.UID_MIN = int(fields[1])
            continue
        elif fields[0] == "UID_MAX":
            Users.UID_MAX = int(fields[1])
            continue
        elif fields[0] == "SYS_UID_MIN":
            Users.SYS_UID_MIN = int(fields[1])
            continue
        elif fields[0] == "SYS_UID_MAX":
            Users.SYS_UID_MAX = int(fields[1])
            continue
        else:
            continue

    # Check access to sudoers
    try:
        CHECK_SUDO = open(Config.SUDO_FILE, 'r')
        Users.SUDO_CONTENT = CHECK_SUDO.readlines()
    except IOError:
        sys.exit('Unable to open ' + Config.SUDO_FILE)

    # Get all users from the system into a table
    Users.USERS = pwd.getpwall()

    # Get all of the logins from WTMP
    # Open new process and run the last command
    p = subprocess.Popen(Config.LAST_CMD + Config.WTMP_FILE,
                         shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Loop through the lines of output
    for line in p.stdout.readlines():
        # If running on Python 3 or above
        if(sys.version_info[0] >= 3):
            row = line.decode().strip().split()
        else:
            row = str(line).strip().split()

        if(len(row) > 0):
            Users.LOGINS.append(row)

# Get all system users (In system UID range), with login times


def get_system_users():
    users_table = []
    for x in Users.USERS:
        if(x[2] <= Users.SYS_UID_MAX):
            if is_sudo(x[0]):
                sudo = "yes"
            else:
                sudo = "no"
            last_login = get_last_login(x[0])
            users_table.append([x[2], x[0], x[5], x[6], sudo, last_login])
    return users_table

# Get all system users (In system UID range), with login times and display GECOS and group ID


def get_system_full():
    users_table = []
    for x in Users.USERS:
        if(x[2] <= Users.SYS_UID_MAX):
            if is_sudo(x[0]):
                sudo = "yes"
            else:
                sudo = "no"
            last_login = get_last_login(x[0])
            gecos = x[4]
            # Truncate comment field to stop output being huge
            gecos = (gecos[:16] + "..") if len(gecos) > 18 else gecos
            if(gecos == ""):
                gecos = "None"
            users_table.append(
                [x[2], x[0], x[3], gecos, x[5], x[6], sudo, last_login])
    return users_table

# Get all non-system users (In user UID range), with login times


def get_users():
    users_table = []
    for x in Users.USERS:
        if(Users.UID_MIN <= x[2] <= Users.UID_MAX):
            if is_sudo(x[0]):
                sudo = "yes"
            else:
                sudo = "no"
            last_login = get_last_login(x[0])
            users_table.append([x[2], x[0], x[5], x[6], sudo, last_login])
    return users_table

# Get all non-system users (In user UID range), with login times and display GECOS and group ID


def get_users_full():
    users_table = []
    for x in Users.USERS:
        if(Users.UID_MIN <= x[2] <= Users.UID_MAX):
            if is_sudo(x[0]):
                sudo = "yes"
            else:
                sudo = "no"
            last_login = get_last_login(x[0])
            gecos = x[4]
            # Truncate comment field to stop output being huge
            gecos = (gecos[:16] + "..") if len(gecos) > 18 else gecos
            if(gecos == ""):
                gecos = "None"
            users_table.append(
                [x[2], x[0], x[3], gecos, x[5], x[6], sudo, last_login])
    return users_table

# Get all users, and login times


def get_all_users():
    users_table = []
    for x in Users.USERS:
        if is_sudo(x[0]):
            sudo = "yes"
        else:
            sudo = "no"
        last_login = get_last_login(x[0])
        users_table.append([x[2], x[0], x[5], x[6], sudo, last_login])
    return users_table

# Get all users, and login times and display GECOS and group ID


def get_all_users_full():
    users_table = []
    for x in Users.USERS:
        if is_sudo(x[0]):
            sudo = "yes"
        else:
            sudo = "no"
        last_login = get_last_login(x[0])
        gecos = x[4]
        # Truncate comment field to stop output being huge
        gecos = (gecos[:16] + "..") if len(gecos) > 18 else gecos
        if(gecos == ""):
            gecos = "None"
        users_table.append(
            [x[2], x[0], x[3], gecos, x[5], x[6], sudo, last_login])
    return users_table

# Check if a user is in the sudoers file, or sudo groups


def is_sudo(user):
    # If they are in the sudo file (Just checks if their name is listed)
    for line in Users.SUDO_CONTENT:
        if user+" " in line:
            return True

    for line in Users.GROUP_CONTENT:
        fields = line.strip().split(':')
        try:
            fields[0]
        except IndexError:
            continue
        if (fields[0] == "wheel" or fields[0] == "admin" or fields[0] == "sudo"):
            groupusers = fields[3].split(',')
            for groupuser in groupusers:
                if groupuser == user:
                    return True

    return False

# Get the max length of a value in an array (For printing tables with padding)


def get_max_field_length(table):
    max_length = 0
    for x in table:
        if isinstance(x, (pwd.struct_passwd, tuple, list, set)):
            for i in range(len(x)):
                l = len(str(x[i]))
                if l > max_length:
                    max_length = l
        else:
            l = len(str(x))
            if l > max_length:
                max_length = l
    return max_length

# Get the time when a user last logged in


def get_last_login(user):
    # Loop over the array we earlier stored from wtmp
    for x in Users.LOGINS:
        if(x[0] == user):
            login = x[3] + ' ' + x[4] + ' ' + x[5] + ' ' + x[6]
            return login

    return "None found"

###################################
# Display functions for the script
###################################
# Show the scripts header


def show_header():
    print(Color.GREEN + r'''
   ______     __     __  __                   
  / ____/__  / /_   / / / /_______  __________
 / / __/ _ \/ __/  / / / / ___/ _ \/ ___/ ___/
/ /_/ /  __/ /_   / /_/ (__  )  __/ /  (__  ) 
\____/\___/\__/   \____/____/\___/_/  /____/  
                                                                                          
    ''', Color.RESET)

# Show the scripts version


def show_version():
    print(Color.GREEN + r'''Version: %s ''' % (__version__), Color.RESET)

# Print the provided table in a padded / tidy format


def print_table(headers, table):
    header_max = get_max_field_length(headers) + 2
    table_max = get_max_field_length(table) + 2

    if(header_max > table_max):
        column_width = header_max
    else:
        column_width = table_max

    print(Color.GREEN + "".join(str(word).ljust(column_width)
                                for word in headers), Color.RESET)
    for x in table:
        print(Color.CYAN + "".join(str(word).ljust(column_width)
                                   for word in x), Color.RESET)

###################################
# Main features
###################################


def show_system_users(ARGS):
    if ARGS.show_full_output:
        users_table = get_system_full()
        print_table(Config.HEADER_FULL, users_table)

    else:
        users_table = get_system_users()
        print_table(Config.HEADER_STANDARD, users_table)
    return


def show_users(ARGS):
    if ARGS.show_full_output:
        users_table = get_users_full()
        print_table(Config.HEADER_FULL, users_table)

    else:
        users_table = get_users()
        print_table(Config.HEADER_STANDARD, users_table)
    return


def show_all_users(ARGS):
    if ARGS.show_full_output:
        users_table = get_all_users_full()
        print_table(Config.HEADER_FULL, users_table)
    else:
        users_table = get_all_users()
        print_table(Config.HEADER_STANDARD, users_table)
    return

###################################
# Main execution for the script
###################################


def main():
    show_header()
    init_variables()

    PARSER = options()
    ARGS = PARSER.parse_args()

    if ARGS.show_version:
        print(Color.MAGENTA + r"Showing version", Color.RESET)
        print("")
        show_version()
        sys.exit()

    if ARGS.show_system_users:
        print(Color.MAGENTA + r"Showing system users", Color.RESET)
        print("")
        show_system_users(ARGS)
        sys.exit()

    if ARGS.show_users:
        print(Color.MAGENTA + r"Showing standard users", Color.RESET)
        print("")
        show_users(ARGS)
        sys.exit()

    if ARGS.show_all_users:
        print(Color.MAGENTA + r"Showing all users", Color.RESET)
        print("")
        show_all_users(ARGS)
        sys.exit()

    # Catch all, but default just show additional users
    print(Color.MAGENTA + r"Default: Showing standard users", Color.RESET)
    print("")
    show_users(ARGS)
    sys.exit()


if __name__ == '__main__':
    main()
