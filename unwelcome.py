#!/usr/bin/python
import os
import sys
import re
from ConfigParser import RawConfigParser
from collections import Counter
import sqlite3
from datetime import datetime

import subprocess
# Import the configuration parameters
config = RawConfigParser()

config.read('settings.cfg')

audit_log = config.get('Options', 'audit_log')
interval = config.get('Options', 'interval')
interval_count = config.get('Options', 'interval_count')
interval_multiple = config.get('Options', 'interval_multiple')
max_ban = config.get('Options', 'max_ban')



# DB logic for setting up database connection and teardown
def getDB():
	rv = sqlite3.connect('/var/lib/unwelcome/unwelcome.db')
	rv.row_factory = sqlite3.Row
	return rv

def closeDB(error):
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()

def precheck():
	FNULL = open(os.devnull, 'w')
	ret = subprocess.call(['ipset', 'list', 'unwelcome'], stdout=FNULL, stderr=subprocess.STDOUT)

	if ret != 0:
		print "unwelcome ipset must exists"
		sys.exit() 

	return 0 
def parse_log(log):

	LOG = open(log, 'r')	

	ips = Counter()

	for line in LOG:
		#print line
		ip = re.search("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
		if ip:
			ip_addr = ip.group(0)
			#print (ip_addr)
			auth = re.search("Failed password", line)
			if auth:
				#print "adding for %s" % ip_addr
				if (ip_addr.isdigit()):
					print error
				ips.update({ip_addr: 1})
			repeats = re.search("message repeated (\d+) times.*Failed password", line)
			if repeats:
				count = int(repeats.group(1))

				if (ip_addr.isdigit()):
					print error
				#print "adding %s for %s" % (count, ip_addr)
				ips.update({ip_addr: count})
	db = getDB()

	for ip in ips:
		#print "%s hit us %s" % (ip, ips[ip])
		db.execute('INSERT or IGNORE INTO hosts (ip, first_seen, last_seen) VALUES (?,?,?)', (ip, datetime.now(), datetime.now()))
		db.commit()
		
		cur = db.execute("UPDATE hosts SET times_seen=(SELECT times_seen FROM hosts WHERE ip=?)+?, last_seen=? WHERE ip=?", \
			(ip, ips[ip], datetime.now(), ip))
		db.commit()

		if ips[ip] > 10:
			unwelcome(ip)

def times_banned(ip):
	db = getDB()

	cur = db.execute("SELECT times_ban FROM hosts WHERE ip=?", (ip,))
	row = cur.fetchone()

	return row['times_ban']

def unwelcome(ip):
	bans = times_banned(ip)

	if bans == 0:
		ban_period = interval
	else:
		ban_period = interval * (interval_multiple * bans)
	
	#print "adding %s for %s" % (ip, ban_period)	
	db = getDB()

	db.execute('INSERT or IGNORE INTO unwelcome (ip, banned_on, banned_for) VALUES (?,?,?)', (ip, datetime.now(), ban_period))
	db.commit()

	FNULL = open(os.devnull, 'w')
	subprocess.call(['ipset','add', 'unwelcome', ip], stdout=FNULL, stderr=subprocess.STDOUT)
	return 0

def save_ipset():
	file_out = open('/var/lib/unwelcome/restore.ipset', 'w')
	subprocess.call(['ipset', 'save', 'unwelcome'], stdout=file_out)

	return 0

def main():
	precheck()
	
	parse_log(audit_log)	

	save_ipset()

	return 0	
if __name__ == "__main__": main()		
