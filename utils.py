#!/usr/bin/env python
# encoding: utf-8

import subprocess
import os
import sys
import paramiko
import logging
import argparse
import socket
import shlex
import ConfigParser

if os.path.exists('etc/cvm'):
    import MySQLdb

LOG_FILE = '/var/log/cas_net_protect.log'
LOG = logging.getLogger(__name__)

LOG_LEVEL = {
                'debug': logging.DEBUG,
                'info': logging.INFO,
                'warning': logging.WARNING,
                'error': logging.ERROR,
                'critical': logging.CRITICAL
            }

def log_init(loglevel=LOG_LEVEL['debug']):
	logging.basicConfig(level=loglevel, filename=LOG_FILE,
				        format="%(asctime)s %(filename)s %(funcName)s [%(lineno)d] %(levelname)s"
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

class MySQLConnection(object):
    def __init__(self, host='localhost', username='root', password='1q2w3e@4R'):
        self.host = host
        self.username = username
        self.password = password

    def connect_db(self, db='vservice', charset='utf8'):
        try:
            db = MySQLdb.connect(self.host, self.username, self.password, db = db, charset=charset)
        except Exception as e:
            LOG.error("fail to connect mysql server (%s)", str(e))

        return db

    def get_currsor(self, db):
        return db.cursor()

    def close_cursor(self, cursor):
        cursor.close()

    def close_db(self, db):
        db.close()

class NetProtecter(object):
    def __init__(self, config='/etc/cvk/cas_net_protect.conf'):
        self.config = config
        self.ports = { 'black_ports':[], 'white_ips':[] }
        self.deny_ips = { 'deny_ips':[] }
        self.mariadb = { 'enable':False }

    def read_config(self):
        """
            #cas_net_protect.conf
            [ports]
            black_ports=aa,bb
            white_ips=x.x.x.x,y.y.y.y
            [deny_ips]
            deny_ips=x.x.x.x,y.y.y.y
            [mariadb]
            enable=true
        """
        if not os.path.exists(self.config):
            LOG.error("net protecter config not exist.")
            return False

        config_parser = ConfigParser.ConfigParser()
        config_parser.read(self.config)
        try:
            for port in config_parser.get('ports', 'black_ports').split(','):
                self.ports['black_ports'].append(port)
            for ip in config_parser.get('ports', 'white_ips').split(','):
                self.ports['white_ips'].append(ip)

            for ip in config_parser.get('deny_ips', 'deny_ips').split(','):
                self.deny_ips['deny_ips'].append(ip)

            if config_parser.get('mariadb', 'enable') == 'true':
                self.mariadb['enable'] = True
        except Exception as e:
            LOG.error("read config: %s failed.(%s)!", self.config, str(e))
            return False
        return True

    def get_config(self):
        return { 'ports':self.ports, 'deny_ips':self.deny_ips, 'mariadb':self.mariadb }


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

def host_execute_cmd(cmd, shell=True, timeout=False):
    if not shell and isinstance(cmd, str):
        cmd = shlex.split(cmd)

    LOG.debug("Running cmd: %s on host", cmd)

    p = subprocess.Popen(cmd, shell=shell, stderr=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)

    if timeout:
        try:
            out, err = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            LOG.error("cmd: %s run timeout(%ss) on host, exit!" % (cmd, timeout))
            sys.exit(1)
    else:
        out, err = p.communicate()

    if p.returncode != 0:
        LOG.error("cmd: %s run failed, out: %s, err: %s, return_code: %s", cmd, out, err, p.returncode)

    LOG.debug("Running cmd: %s on host success.", cmd)
    return out, err

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
        ssh_instance.close(ssh_client)
    except Exception as exc:
        LOG.error("Run cmd: %s failed on ip %s via ssh! (%s)" % (cmd, ip, str(exc)))
        sys.exit(1)

    LOG.debug("cmd stdout: %s, stderr: %s, exit_code: %s", stdout, stderr, exit_code)

    if exit_code != -1 and exit_code != 0:
        LOG.error("Run cmd: %s failed on %s via ssh(exit_code:%s)", cmd, ip, exit_code)
        raise RuntimeError(stderr.strip() + stdout.strip())

    LOG.debug("Running cmd: %s on %s via ssh success.", cmd, ip)

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

def scp_upload_files(localpath, remotepath, ip, username='root'):
    """ scp upload dir to remote """

    if not is_valid_ip(ip) and not is_valid_ip6(ip):
        LOG.error("ip %s not valid for scp.", ip)
        sys.exit(1)

    if is_valid_ip6(ip):
        ip = '[' + ip + ']'

    cmd = 'timeout 15 scp -r %s %s@%s:%s' %(localpath, username, ip, remotepath)

    try:
        host_execute_cmd(cmd)
        LOG.info("%s run success.", cmd)
    except Exception as e:
        LOG.error("%s run failed.", cmd)
        sys.exit(1)

def mysqldb_search(sqlname):
    """ serch sql in MySQLdb """
    mysql_instance = MySQLConnection()
    try:
        db = mysql_instance.connect_db()
        cursor = mysql_instance.get_currsor(db)
        cursor.execute(sqlname)
        ret = cursor.fetchall()
        mysql_instance.close_cursor(cursor)
        mysql_instance.close_db(db)
    except Exception as e:
        LOG.error("%s failed. (%s)", sqlname, str(e))
        sys.exit(1)

    LOG.debug("%s success.", sqlname)
    return ret

def parse_args(argv):
    top_parser = argparse.ArgumentParser(description='utils')
    top_parser.add_argument('-l', '--loglevel', dest='loglevel', nargs='?', default='debug', help="specify utils log level")

    subparsers = top_parser.add_subparsers(help='operation type')

    host_parser = subparsers.add_parser('host', help='host operation')
    host_parser.add_argument('-c', '--cmd', required=True, dest='cmd', help="specify host run command")
    host_parser.set_defaults(func=host_operation_test)

    ssh_parser = subparsers.add_parser('ssh', help='ssh operation')
    ssh_parser.add_argument('-i', '--ipaddr', required=True, dest='ipaddr', help="specify remote ip addr")
    ssh_parser.add_argument('-c', '--cmd', required=True, dest='cmd', help="specify remote run command")
    ssh_parser.set_defaults(func=ssh_operation_test)

    sftp_parser = subparsers.add_parser('sftp', help='sftp operation')
    sftp_parser.add_argument('-i', '--ipaddr', required=True, dest='ipaddr', help="specify remote ip addr")
    sftp_parser.add_argument('-c', '--cmd', required=True, dest='cmd', help="specify sftp upload or download")
    sftp_parser.add_argument('-l', '--localpath', required=True, dest='localpath', help="specify local file path to upload or download via sftp")
    sftp_parser.add_argument('-r', '--remotepath', required=True, dest='remotepath', help="specify remote path")
    sftp_parser.set_defaults(func=sftp_operation_test)

    scp_parser = subparsers.add_parser('scp', help='scp operation')
    scp_parser.add_argument('-i', '--ipaddr', required=True, dest='ipaddr', help="specify remote ip addr")
    scp_parser.add_argument('-l', '--localpath', required=True, dest='localpath', help="specify local path to upload or download via scp")
    scp_parser.add_argument('-r', '--remotepath', required=True, dest='remotepath', help="specify remote path")
    scp_parser.set_defaults(func=scp_operation_test)

    mysql_parser = subparsers.add_parser('mysql', help='mysql operation')
    mysql_parser.add_argument('-s', '--sql', required=True, dest='sql', help="specify sqlname to search")
    mysql_parser.set_defaults(func=mysql_operation_test)

    all_parser = subparsers.add_parser('all', help='netprotect operation for all config')
    all_parser.add_argument('-e', '--enable', action='store_true', help="enable all protect")
    all_parser.add_argument('-d', '--disable', action='store_true', help="disable all protect")
    all_parser.set_defaults(func=all_operation_test)

    args = top_parser.parse_args(argv)
    return args

def ssh_operation_test(argv):
    cmd = argv.cmd
    ip = argv.ipaddr

    out, err = ssh_execute_cmd(cmd, ip)
    print "[%s] retutn: %s" % (cmd, out)


def sftp_operation_test(argv):
    cmd = argv.cmd
    ip = argv.ipaddr
    localpath = argv.localpath
    remotepath = argv.remotepath

    if cmd == 'put':
        sftp_upload_file(localpath, remotepath, ip)
    elif cmd == 'get':
        sftp_download_file(remotepath, localpath, ip)

def scp_operation_test(argv):
    ip = argv.ipaddr
    localpath = argv.localpath
    remotepath = argv.remotepath

    scp_upload_files(localpath, remotepath, ip)

def host_operation_test(argv):
    cmd = argv.cmd

    out, err = host_execute_cmd(cmd)
    print "[%s] return: %s " % (cmd, out)

def mysql_operation_test(argv):
    sqlname = argv.sql

    ret = mysqldb_search(sqlname)
    print ret

def all_operation_test(argv):
    p = NetProtecter()
    if argv.enable:
        print "net protect enable all"
    elif argv.disable:
        print "net protect disable all"
    else:
        print "missing action."
        return

    if p.read_config():
        print "net protect read config ok"
    else:
        print "net protect read config failed"
        sys.exit(1)
    print "config: %s" % (p.get_config())

def main():
    log_init()

    try:
        argv = parse_args(sys.argv[1:])
        if argv.loglevel:
            LOG.setLevel(LOG_LEVEL[argv.loglevel])
        argv.func(argv)
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)

if __name__ == '__main__':
    sys.exit(main())
