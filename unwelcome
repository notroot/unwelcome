#!/usr/bin/python
import os
import sys
import re
from ConfigParser import RawConfigParser
from collections import Counter
import sqlite3
from datetime import datetime, date

import subprocess
# Import the configuration parameters
config = RawConfigParser()

config.read('settings.cfg')

audit_log = config.get('Options', 'audit_log')
interval = config.getint('Options', 'interval')
interval_count = config.getint('Options', 'interval_count')
interval_multiple = config.getint('Options', 'interval_multiple')
max_ban = config.getint('Options', 'max_ban')



conn = sqlite3.connect('/var/lib/unwelcome/unwelcome.db')
conn.row_factory = sqlite3.Row

# DB logic for setting up database connection and teardown
def connectDB():
	rv = sqlite3.connect('/var/lib/unwelcome/unwelcome.db')
	rv.row_factory = sqlite3.Row
	return rv

def getDB():
	#if not hasattr(g, 'sqlite_db'):
	#	g.sqlite_db = connectDB()
	#return g.sqlite_db
	return conn


def precheck():
	FNULL = open(os.devnull, 'w')
	ret = subprocess.call(['ipset', 'list', 'unwelcome'], stdout=FNULL, stderr=subprocess.STDOUT)

	if ret != 0:
		print "unwelcome ipset must exists"
		sys.exit() 

	return 0 

def getTime(line):
	regex = '^(\w{3}\s{1,2}\d{1,2}\s\d\d:\d\d:\d\d).*'

	match = re.match(regex, line)

	if match:
		date_string = match.groups()[0]
	else:
		print "line not matchin"
		return 99

	year = date.today().year
	date_string = "%s %s" % (date_string, year)
	date_tm = datetime.strptime(date_string, "%b %d %X %Y")
	
	return date_tm

def parseLog(log):
	db = getDB()
	banned = 0
	
	cur = db.execute('SELECT setting FROM configs WHERE config="last_run"')
	last_run = cur.fetchone()[0]
	last_run = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
	
	print "Last run: %s" % last_run

	LOG = open(log, 'r')	

	ips = Counter()

	for line in LOG:
		#print line
		#print "Seconds old: %s" % secondsOld(line)
		line_time = getTime(line)
		
		if line_time < last_run:
			continue
			
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
				count = int(repeats.group(1)) - 1

				if (ip_addr.isdigit()):
					print error
				#print "adding %s for %s" % (count, ip_addr)
				ips.update({ip_addr: count})

	for ip in ips:
		#print "%s hit us %s" % (ip, ips[ip])
		db.execute('INSERT or IGNORE INTO hosts (ip, first_seen, last_seen) VALUES (?,?,?)', (ip, datetime.now(), datetime.now()))
		db.commit()
		
		cur = db.execute("UPDATE hosts SET times_seen=(SELECT times_seen FROM hosts WHERE ip=?)+?, last_seen=? WHERE ip=?", \
			(ip, ips[ip], datetime.now(), ip))
		db.commit()

		if ips[ip] > interval_count:
			banned += 1
			unwelcome(ip)

	db.execute("UPDATE configs SET setting= DATETIME('now') where config='last_run'")
	db.commit()

	print "Banned %s IPs" % banned

def timesBanned(ip):
	db = getDB()

	cur = db.execute("SELECT times_banned FROM hosts WHERE ip=?", (ip,))
	row = cur.fetchone()

	return int(row['times_banned'])

def unwelcome(ip):
	bans = timesBanned(ip)
	
	if bans == 0:
		ban_period = interval
	else:
		ban_period = interval ** bans
		if ban_period > max_ban:
			ban_period = max_ban
	
	print "adding %s for %s" % (ip, ban_period)	
	db = getDB()

	db.execute('INSERT or IGNORE INTO unwelcome (ip, banned_on, banned_for) VALUES (?,?,?)', (ip, datetime.now(), ban_period))
	db.commit()

	FNULL = open(os.devnull, 'w')
	subprocess.call(['ipset','add', 'unwelcome', ip], stdout=FNULL, stderr=subprocess.STDOUT)
	
	db.execute('UPDATE hosts SET times_banned=(SELECT times_banned FROM hosts WHERE ip=?)+1 WHERE ip=?',(ip,ip))
	db.commit()

	return 0
	
def cleanList():
	db = getDB()
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
			subprocess.call(['ipset','del', 'unwelcome', ip], stdout=FNULL, stderr=subprocess.STDOUT)
			removed += 1
			
		db.execute("DELETE FROM unwelcome WHERE date(banned_on, '+%s days') <= date('now');" % interval)
		db.commit()
		
	print "Remove %s IPs from unwelcome" % removed

def saveIPset():
	file_out = open('/var/lib/unwelcome/restore.ipset', 'w')
	subprocess.call(['ipset', 'save', 'unwelcome'], stdout=file_out)

	return 0

def main():
	precheck()
	
	print "Running %s" % datetime.now().ctime()
	parseLog(audit_log)	

	cleanList()
	
	saveIPset()

	return 0	

if __name__ == "__main__": 
	main()		
