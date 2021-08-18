#!/usr/bin/env python
# encoding: utf-8

from genericpath import exists
import subprocess
import os
import sys
import paramiko
import logging
import argparse
import socket

LOG_FILE = '/var/log/cas_net_protect.log'
LOG = logging.getLogger(__name__)

LOG_LEVEL = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

def log_init(loglevel=LOG_LEVEL['debug']):
	logging.basicConfig(level=loglevel, filename=LOG_FILE,
				        format="%(asctime)s %(name)s[%(lineno)d] %(levelname)s"
				        " %(message)s", datefmt='%Y-%m-%d %H:%M:%S %a')

class SSHConnection(object):
    def __init__(self, ip, port=22, timeout=15):
        self.ip=ip
        self.port=port
        self.timeout=timeout

    def connect(self):
        try:
            s = paramiko.SSHClient()
            s.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #allow connect host that not in known_hosts
            s.connect(self.ip, port=self.port, timeout=self.timeout, allow_agent=False)
            return s
        except Exception as exc:
            LOG.error("ssh connection failed: %s" % str(exc))
            sys.exit(1)
    
    def close(self, s):
        s.close()

class SFTPConnection(object):
    def __init__(self, ip, user='root', passwd=None, key=None, port=22, timeout=15):
        self.ip = ip
        self.user = user
        self.passwd = passwd
        self.key = key
        self.port = port
        self.timeout = timeout

    def connect(self):
        try:
            handle = paramiko.Transport(self.ip, self.port)
            if self.passwd:
                handle.connect(username=self.user, password=self.passwd)
            elif self.key:
                handle.connect(username=self.user, pkey=self.key)
            else:
                LOG.error("Missing passwd or key for sftp!")
                sys.exit(1)
            sftp = paramiko.SFTPClient.from_transport(handle)
            return sftp
        except Exception as exc:
            LOG.error("sftp connect failed: %s" % str(exc))
            sys.exit(1)

    def close(self, s):
        s.close()

def ssh_execute_cmd(cmd, ip):
    """ Run cmd via ssh
        :param ip:  remote ip
        :param cmd: command to run
        :return:    (stdout, stderr) of cmd execution
    """
    
    LOG.debug("Running cmd: %s on %s via ssh", cmd, ip)

    ssh_instance = SSHConnection(ip)
    try:
        ssh_client = ssh_instance.connect()
        istream, ostream, estream = ssh_client.exec_command(cmd)
        stdout = ostream.read()
        stderr = estream.read()
        istream.close()
        exit_code = ostream.channel.recv_exit_status()
    except Exception as exc:
        LOG.error("Run cmd: %s failed on ip %s via ssh! (%s)" % (cmd, ip, str(exc)))
        sys.exit(1)
    
    LOG.debug("cmd stdout: %s, stderr: %s, exit_code: %s", stdout, stderr, exit_code)
    ssh_instance.close(ssh_client)

    if exit_code != -1 and exit_code != 0:
        LOG.error("Run cmd: %s failed on %s via ssh(exit_code:%s)", cmd, ip, exit_code)
        raise RuntimeError(stderr.strip() + stdout.strip())

    return (stdout, stderr)

def sftp_upload_file(l_filepath, r_dir, ip, username='root', password=None):
    """ upload file via sftp
        :param l_filepath: local file path
        :param r_dir: remote dir
        :param ip: remote ip
        :param username: remote username to create sftp
        :param passsword: remote password
    """
    LOG.debug("upload file: %s to dir: %s (at %s) via sftp", l_filepath, r_dir, ip)

    if not password:
        keypath = '/{0}/.ssh/id_rsa'.format(username)
        pkey = paramiko.RSAKey.from_private_key_file(keypath)
        sftp_instance = SFTPConnection(ip, user=username, key=pkey)
    else:
        sftp_instance = SFTPConnection(ip, user=username, passwd=password)

    try:
        sftp_client = sftp_instance.connect()
        try:
            sftp_client.chdir(r_dir)
        except:
            sftp_client.mkdir(r_dir)

        file_name = os.path.basename(l_filepath)
        r_filepath = '{0}/{1}'.format(r_dir, file_name)
        sftp_client.put(l_filepath, r_filepath)
        sftp_instance.close(sftp_client)

        LOG.debug("upload file %s to dir %s (at %s) success!" % (l_filepath, r_dir, ip))
    except Exception as exc:
        LOG.error("upload file %s to dir %s (at %s) failed! (%s)" % (l_filepath, r_dir, ip, str(exc)))
        sys.exit(1)

def sftp_download_file(r_filepath, l_dir, ip, username='root', password=None):
    """ download file via sftp
        :param r_filepath: remote file
        :param l_dir: local dir
        :param ip: remote ip
        :param username: remote username to create sftp
        :param passsword: remote password
    """

    LOG.debug("download file： %s(at %s) to dir: %s via sftp", r_filepath, ip, l_dir)

    if not password:
        keypath = '/{0}/.ssh/id_rsa'.format(username)
        pkey = paramiko.RSAKey.from_private_key_file(keypath)
        sftp_instance = SFTPConnection(ip, user=username, key=pkey)
    else:
        sftp_instance = SFTPConnection(ip, user=username, passwd=password)

    try:
        sftp_client = sftp_instance.connect()

        if not os.path.exists(l_dir):
            os.makedirs(l_dir)

        file_name = os.path.basename(r_filepath)
        l_filepath='{0}/{1}'.format(l_dir, file_name)
        sftp_client.get(r_filepath, l_filepath)
        sftp_instance.close(sftp_client)
        LOG.debug("download file %s to %s from %s sucess!" % (r_filepath, l_dir, ip))
    except Exception as exc:
        LOG.error("download file %s to %s from %s failed!(%s)" % (r_filepath, l_dir, ip, str(exc)))
        sys.exit(1)

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except:
        return False
    return True

def is_valid_ip6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except:
        return False
    return True

def usage():
    print "python untils.py [-t] ssh [-i] ip [-c] cmd [-l] loglevel"
    print "python untils.py [-t] sftp [-c] put|get [-i] ip [-f] file [-d] dir [-l] loglevel"


def parse_input_args():
    desc = (
        'test untils.py'
    )

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-t', '--test', dest='test', help="specify test name")
    parser.add_argument('-i', '--ipaddr', dest='ipaddr', help="specify remote ip addr")
    parser.add_argument('-c', '--cmd', dest='cmd', help="specify remote run command")
    parser.add_argument('-f', '--file', dest='file', help="specify file path to upload via sftp")
    parser.add_argument('-d', '--dir', dest='dir', help="specify remote dir")
    parser.add_argument('-l', '--loglevel', dest='loglevel', nargs='?', default='debug', help="specify log level")

    LOG.debug("input args: %s", sys.argv[1:])
    if len(sys.argv) <=1 or (len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']):
        usage()
        sys.exit(0)

    args = parser.parse_args()
    if args.ipaddr and not is_valid_ip(args.ipaddr) and not is_valid_ip6(args.ipaddr):
        print "Invalid remote ip"
        sys.exit(1)

    return args.__dict__

def ssh_test(cmd, ip):
    out, err = ssh_execute_cmd(cmd, ip)
    print "[%s] retutn: %s" % (cmd, out)

def sftp_test(cmd, filepath, dir, ip):
    if cmd == 'put':
        sftp_upload_file(filepath, dir, ip)
    elif cmd == 'get':
        sftp_download_file(filepath, dir, ip)

def test_run():
    log_init()
    args_dict = parse_input_args()
    if args_dict['loglevel']:
        LOG.setLevel(LOG_LEVEL[args_dict['loglevel']])

    if not args_dict['test']:
        raise RuntimeError("miss test name!")

    if args_dict['test'] == "ssh":
        ssh_test(args_dict['cmd'], args_dict['ipaddr'])
    elif args_dict['test'] == "sftp":
        cmd = args_dict['cmd']
        filepath = args_dict['file']
        dir = args_dict['dir']
        sftp_test(cmd, filepath, dir, args_dict['ipaddr'])
    else:
        print "Not support test: %s" % args_dict['test']


if __name__ == '__main__':
    try:
        test_run()
    except Exception as exc:
        LOG.error("untils test run failed: %s", str(exc))
