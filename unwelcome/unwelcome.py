#!/usr/bin/env python3
from collections import Counter
from datetime import datetime, date
import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys

class UnwelcomeError(Exception):
    def __init__(self, message="Generic Unwelcome Error"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message}'


class Unwelcome:
    def __init__(self, config_file=None, dry_run=False, log_ips=False):

        self.audit_log = "/var/log/auth.log"
        self.log_dir = "/var/lib/unwelcome/logs"
        self.interval = 3
        self.interval_count = 21
        self.interval_multiple = 3
        self.max_ban = 90

        self.dry_run = dry_run
        self.log_ips = log_ips

        if config_file:
            self.__load_config(config_file)

        if not os.path.isdir(self.log_dir):
            os.mkdirs(self.log_dir, exist_ok=True)

        self.log_file = os.path.join(self.log_dir, "unwelcome.log")
        if self.dry_run:
            # log to console for dry-run
            logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
        else:
            logging.basicConfig(filename=self.log_file, filemode='a', format='%(asctime)s - %(message)s', level=logging.INFO)

        self.conn = self.__connect_db()

    def __load_config(self, config_file):
        """ load configuration parameters from file """
        if not os.path.isfile(config_file):
            raise UnwelcomeError(f"Unable to locate config file {config_file}")

        import configparser
        config = configparser.RawConfigParser()

        config.read(config_file)

        try:
            self.audit_log = config.get('Options', 'audit_log')
            self.interval = config.getint('Options', 'interval')
            self.interval_count = config.getint('Options', 'interval_count')
            self.interval_multiple = config.getint('Options', 'interval_multiple')
            self.max_ban = config.getint('Options', 'max_ban')
        except configparser.NoSectionError:
            raise UnwelcomeError("Missing [Options] section in config")
        except configparser.NoOptionError as e:
            raise UnwelcomeError(f"Error processing config file: {e}")

    def __connect_db(self):
        needs_init = False
        if not os.path.isdir("/var/lib/unwelcome"):
            os.mkdir("/var/lib/unwelcome")

        if not os.path.isfile('/var/lib/unwelcome/unwelcome.db'):
            needs_init = True

        rv = sqlite3.connect('/var/lib/unwelcome/unwelcome.db')
        rv.row_factory = sqlite3.Row

        if needs_init:
            with open('schema.sql') as schemaf:
                rv.executescript(schemaf.read())

        return rv

    def __get_db(self):
        return self.conn

    def precheck(self):
        FNULL = open(os.devnull, 'w')
        ret = subprocess.call(['ipset', 'list', 'unwelcome'], stdout=FNULL, stderr=subprocess.STDOUT)

        if ret != 0:
            print("unwelcome ipset must exists", file=sys.stderr)
            sys.exit(1)

        return 0

    def get_time(self, line):
        regex = r'^(\w{3}\s{1,2}\d{1,2}\s\d\d:\d\d:\d\d).*'

        match = re.match(regex, line)

        if match:
            date_string = match.groups()[0]
        else:
            return None

        year = date.today().year
        date_string = "%s %s" % (date_string, year)
        date_tm = datetime.strptime(date_string, "%b %d %X %Y")

        return date_tm

    def process_log(self, log=None, from_scratch=False):
        if not log:
            log = self.audit_log

        logging.info(f"Processing {log}")

        db = self.__get_db()
        banned = 0
        lines_matched = 0
        cur = db.execute('SELECT setting FROM configs WHERE config="last_run"')
        last_run = cur.fetchone()[0]
        last_run = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
        if from_scratch:
            last_run = datetime.strptime("1970-01-01 00:00:01", "%Y-%m-%d %H:%M:%S")

        logging.info(f"Last run: {last_run}")
        LOG = open(log, 'r')

        ips = Counter()
        users = Counter()

        for line in LOG:
            line_time = self.get_time(line)
            if not line_time:
                # unable to process time from line
                continue
            elif line_time < last_run:
                continue

            # message repeated 4 times: [ Failed password for root from 87.241.1.186 port 58263 ssh2]
            repeats = re.match(r".*message repeated (\d+) times: \[ Failed password for (?:invalid user )?(\w+) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*", line)
            if repeats:
                lines_matched += 1
                count = int(repeats.group(1))
                user_name = repeats.group(2)
                ip_addr = repeats.group(3)

                ips.update({ip_addr: count})
                users.update({user_name: count})
                continue

            # Failed password for invalid user steam from 64.225.102.125 port 36144 ssh2
            match = re.match(r".*Failed password for (?:invalid user )?(\w+) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*", line)
            if match:
                lines_matched += 1
                user_name = match.group(1)  # maybe autoban on root?
                ip_addr = match.group(2)

                ips.update({ip_addr: 1})
                users.update({user_name: 1})
                continue

        for ip in ips:
            if ips[ip] > self.interval_count:
                banned += 1

            if self.dry_run:
                continue

            db.execute('INSERT or IGNORE INTO hosts (ip, first_seen, last_seen) VALUES (?,?,?)', (ip, datetime.now(), datetime.now()))
            db.commit()

            cur = db.execute("UPDATE hosts SET times_seen=(SELECT times_seen FROM hosts WHERE ip=?)+?, last_seen=? WHERE ip=?",
                             (ip, ips[ip], datetime.now(), ip))

            db.commit()
            if ips[ip] > self.interval_count:
                self.add_unwelcome(ip)

        if not self.dry_run:
            db.execute("UPDATE configs SET setting= DATETIME('now','localtime') WHERE config='last_run';")
            db.commit()

        self.log_ips_json(ips)

        logging.info(f"Processed {lines_matched} matching lines")
        logging.info(f"Banned {banned} IPs")

    def log_ips_json(self, ips):
        """ log all the seen IPs to a json with seen count, useful for tuning """
        if self.log_ips:
            date_code = datetime.now().strftime("%Y%m%d-%H%M%S")
            outfile_name = f"failed_auth_ips_{date_code}.json"
            outfile_path = os.path.join(self.log_dir, outfile_name)
            logging.info(f"Saving seen IPs to {outfile_path}")
            with open(outfile_path, 'w') as out_json:
                json.dump(ips, out_json)

    def get_times_banned(self, ip):
        db = self.__get_db()

        cur = db.execute("SELECT times_banned FROM hosts WHERE ip=?", (ip,))
        row = cur.fetchone()

        return int(row['times_banned'])

    def add_unwelcome(self, ip):
        """ calculate ban period and add IP address to the unwelcome table
        updates DB with number of times banned and date of ban for later unbanning
        """
        times_banned = self.get_times_banned(ip)
        times_banned += 1

        if times_banned == 0:
            ban_period = self.interval
        if times_banned > 100:  # safety cutoff
            ban_period = self.max_ban
        else:
            ban_period = self.interval ** times_banned

        if ban_period > self.max_ban:
            ban_period = self.max_ban

        logging.info(f"Adding {ip} for {ban_period}")
        if self.dry_run:
            return

        db = self.__get_db()

        db.execute('INSERT or IGNORE INTO unwelcome (ip, banned_on, banned_for) VALUES (?,?,?)', (ip, datetime.now(), ban_period))
        db.commit()

        FNULL = open(os.devnull, 'w')
        subprocess.call(['ipset', 'add', 'unwelcome', ip], stdout=FNULL, stderr=subprocess.STDOUT)

        db.execute('UPDATE hosts SET times_banned=? WHERE ip=?', (times_banned, ip))
        db.commit()

        return 0

    def clean_list(self):
        if self.dry_run:
            return

        db = self.__get_db()
        removed = 0

        cur = db.execute("SELECT DISTINCT banned_for FROM unwelcome")
        ban_intervals = cur.fetchall()

        for interval in ban_intervals:
            interval = int(interval['banned_for'])
            cur = db.execute("SELECT ip FROM unwelcome WHERE date(banned_on, '+%s days') <= date('now');" % interval)
            ips = cur.fetchall()

            for ip in ips:
                ip = ip['ip']
                FNULL = open(os.devnull, 'w')
                subprocess.call(['ipset', 'del', 'unwelcome', ip], stdout=FNULL, stderr=subprocess.STDOUT)
                removed += 1

            db.execute("DELETE FROM unwelcome WHERE date(banned_on, '+%s days') <= date('now');" % interval)
            db.commit()

        logging.info(f"Removed {removed} IPs from unwelcome list")

    def save_ipset(self):
        if self.dry_run:
            return

        file_out = open('/var/lib/unwelcome/restore.ipset', 'w')
        subprocess.call(['ipset', 'save', 'unwelcome'], stdout=file_out)

        return 0


def main():
    parser = argparse.ArgumentParser(description="Unwelcome process the audit log for failed login attempts and creates an ipset of unwelcome IPs")
    parser.add_argument("--log", type=str, help="Path to log to parse, defaults to /var/log/auth.log")
    parser.add_argument("--from-scratch", action="store_true", help="Process logfile from begining instead of last run time")
    parser.add_argument("--dry-run", action="store_true", help="Parse log and count up bans only, do not altere database or ipset")
    parser.add_argument("--log-ips", action="store_true", help="Store seen IPs to JSON for each run, useful for tuning thresholds")
    args = parser.parse_args()

    uw = Unwelcome(dry_run=args.dry_run, log_ips=args.log_ips)
    uw.precheck()

    uw.process_log(from_scratch=args.from_scratch)

    uw.clean_list()

    uw.save_ipset()

    return


if __name__ == "__main__":
    sys.exit(main())
