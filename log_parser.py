#!/usr/bin/env python

#-----------------------------------------------------------------------------------------------------------------------
# INFO:
#-----------------------------------------------------------------------------------------------------------------------

"""
Author: Niraj Nakrani
License: Apache 2.0
Description: Log processor testing command-line utility.
"""


#-----------------------------------------------------------------------------------
#importS:
#-----------------------------------------------------------------------------------

import re
import sqlite3
import os

# REMOVE DATABSE IF ALREADY EXIST
if os.path.exists('mydb.db'):
    os.remove('mydb.db')

# Create Database
con = sqlite3.connect('mydb.db')
c = con.cursor()

#Create Tables
c.execute("CREATE TABLE Events(date TEXT, time TEXT, severity TEXT, event_id INTEGER, hostname TEXT, protocol TEXT, event_type TEXT, source_ip TEXT, destination_ip TEXT, user_name TEXT)")
#cursor.execute("CREATE TABLE AccessEvent(date TEXT, time TEXT, severity TEXT, event_id INTEGER, source_ip TEXT, destination_ip TEXT, user_name TEXT)")
con.commit()

# Check if log file exist
if os.path.isfile('log.txt'):
	print("Reading log.txt file")
else:
	print("Log.txt file missing: Kindly place the log.txt file in same directory")
	con.close()
	exit() 

# Open the file in read mode
f = open("log.txt", "r")

count_lines = 0
# Read the file line by line
for line in f.readlines():
        count_lines+=1
	tokens = line.split()
	#INITIALISE THE LOCAL VARIABLE
        source = 0

	date = None
	time = None
	severity = None
	eventid = None
	hostname = None
	protocol = None
	srcip = None
	dstip = None
	eventtype = None
	username = None

	for element in tokens:
		#REGEX TO MATCH DATE
		if (re.match('\d{4}[-/]\d{2}[-/]\d{2}',element)):
			date = element
		#REGEX TO MATCH TIME
		elif (re.match('\d{2}[:/]\d{2}[:/]\d{2}[./]\d{6}', element)):
			time = element
		#REGEX TO MATCH SEVERITY
		elif (re.match('\Alow|\Amed|\Ahig|\Adeb|\Acri|\ACRI', element)):
			severity = element
		#REGEX TO MATCH EVENTID
		elif (re.match('\d{4}', element)):
			eventid = element
		#REGEX TO MATCH HOSTNAME
		elif (element.startswith('host') & element.endswith('.com')):
			hostname = element
		#REGEX TO MATCH SOURCE AND DESTINATION IP
		elif (re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', element)):
			if source:
				dstip = element
			else:
#				print("source =  %s" %element)
				srcip = element
				source = 1
		#REGEX TO MATCH PROTOCOL
		elif (re.match('^[A-Z]{3}$|^[A-Z]{4}', element)):
#			print(element)
			protocol = element
		#REGEX TO MATCH EVENTTYPE
		elif (element.startswith('CVE-')):
#			print(element)
			eventtype = element
		#REGEX TO MATCH USENAME
		elif (re.match('\A[a-z]', element)):
#			print(element)
			username = element

	#INSERT THE ROW INTO DATABSE BASED ON EVENT TYPE
	if  eventtype is None:
		# Insert in Access event table
                c.execute("INSERT INTO Events (date, time, severity, event_id, source_ip, destination_ip, user_name) VALUES(?,?,?,?,?,?,?)", (date, time, severity, eventid, srcip, dstip, username))
                con.commit()
	elif eventtype is not None:
		# Insert into CVE event table
                c.execute("INSERT INTO Events (date, time, severity, event_id, hostname, protocol, event_type) VALUES(?,?,?,?,?,?,?)", (date, time, severity, eventid, hostname, protocol, eventtype))
                con.commit()

#TEST 1 : VALIDATE THE NUMBER OF LINES IN THE FILE TO NUMBER ROW IN THE DATABASE
print("No. of Lines processed = %d" %count_lines)

c.execute("select COUNT(*) FROM Events")
data = c.fetchone()

print("No of Records in Database Table = %d" %data[0])

if count_lines == data[0]:
    print("No. of Entries in Database Validated Successfully")
else:
    print("Database Validation Failed")

#TEST 2 : PRINT THE NUMBER OF CRITICAL CVE- EVENTS IN THE DATABASE
c.execute("select COUNT(*) FROM Events WHERE event_type LIKE 'CVE-%' AND severity = 'critical'")
data = c.fetchone()

print("No of critical CVE Events in database = %d" %data[0])

#CLOSING THE DABASE CONNECTION
con.close()
#CLOSING THE LOG FILE
f.close()
