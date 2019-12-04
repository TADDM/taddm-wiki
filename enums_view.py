#!/usr/bin/env ../../bin/jython_coll_253
#
# It is assumed that this script is located in a directory
# which is not part of the standard TADDM directory structure.
# This minimizes the risk of removing the script inadvertantly as part of an upgrade.
#
# To launch the TADDM jython environment, the first line should point to the 
# jython_coll script in the $COLLATION_HOME/bin directory. 
# Use the relative location of the directory to initialize the environment.
#
# If for example, the script is stored in $COLLATION_HOME/usr/bin
# use the following path to launch the jython interpreter and initiate the TADDM environment
#	../../dist/bin/jython_coll_253 
#
# If the script is stored in $COLLATION_HOME/bin
# use the following path to launch the jython interpreter and initiate the TADDM environment
#	./jython_coll_253 
#
import sys 
import traceback
import getopt
import os
import inspect
import subprocess
from subprocess import Popen, PIPE
from getopt import GetoptError

from org.apache.log4j import *
from org.apache.log4j.xml import *

import java.lang
from java.lang import System
from java.io import File
from java.io import FileInputStream
from java.util import Properties

from com.collation.platform.model.topology import enums as enums
from com.collation.platform.model.topology.enums import *


	
#######################################################################################################
#######################################################################################################
class Usage(Exception):
	def __init__(self, msg):
		
		self.msg = msg


#######################################################################################################
#######################################################################################################
class Quit(Exception):
	def __init__(self,rc=0,msg=None):

		self.rc = rc
		self.msg = msg
	   

#######################################################################################################
#######################################################################################################
class Exit(Exception):
	def __init__(self, rc=0,msg=None):

		self.msg = msg
		self.rc = rc
			
	def leave(self):
		raise SystemExit()


###########################################################################
###########################################################################
def show_help():
	
	pref = "\t\t"
	delim = "\t"
	print "\n" + delim + "This script creates and executes sql scripts to create a database objects that contain the TADDM enumeration specifications"
	print "\n" + delim + "The following database objects are created: a table named " + tableName + " and a view named " + viewName
	print "\n" + delim + "The sql sripts are stored as create_" + scriptSuffix + " and drop_" +  scriptSuffix + " in " + scriptLocation   	
	print "\n" + delim + "Messages from this script are logged in " + logfileName 
	print ""
	
	if "WINDOWS" in java.lang.System.getProperty("os.name").upper():
		ext1 = "bat"
	else:
		ext1 = ext
	print delim + "INVOCATION:\n" 
	print pref + prog + "." + ext1 + " <action> [-u|-user <username>] [-p|--password <password>] [-q|--quiet] [-h|--help]"
	print ""
	print pref + "<action>\t\t"+ delim +"action to perform. Valid actions are:"
	print pref + "\t\t" + delim + "\t\tscripts\t\tCreates sql scripts to create the database objects."
	print pref + "\t\t" + delim + "\t\tcreate\t\tExecutes the create_" + prog + "_table.sql script" 
	print pref + "\t\t" + delim + "\t\tremove\t\tExecutes the drop_" + prog + "_table.sql script"
	print pref + "\t\t" + delim + "\t\thelp\t\tShow this help informaiton"
	print pref + "-u, --user  <user>\t" + delim +"User to perform the action as. Default value is 'administrator'"
	print pref + "-p, --password  <password>" + delim +"Password that authenticates this user. Default value is 'collation'"
	print pref + "-q, --quiet\t\t" + delim + "Suppress output to the console"
	print pref + "-h, --help\t\t"+delim + "Displays this help message." 
	print ""
	print delim + "EXAMPLES:"
	print ""
	print pref + "To create sql scripts that can be used to create the enumeration database objects, use the 'scripts' option"
	print pref + "\t" + prog + "." + ext + " scripts "
	print ""
	print pref + "To create the enumeration database objects, use the 'create' action after the scripts have been created"
	print pref + "\t" + prog + "." + ext + " create "
	print ""
	print pref + "To drop the enumeration database objects, use the 'remove' action after the scripts have been created"
	print pref + "\t" + prog + "." + ext + " remove "
	print ""
	print pref + "To use specific set of credentials to log on to TADDM use the -u and -p options"
	print pref + "\t" + prog + "." + ext + " <action> -u <your-user> -p <your-password> "
	print ""
	print ""
	raise SystemExit()

#################################################	
def getScriptFileName(type):
	outputFile = scriptLocation + os.sep + type + "_" + scriptSuffix
	return outputFile
	
####################################################################################	
def saveFile(content, type):
	
	outputFile = getScriptFileName(type)
	
	outfile = open(outputFile,"w")
	outfile.write(content)
	outfile.flush()
	outfile.close()
	msg = type + " sql script successfully written to: " + str(outputFile)
	logit("INFO",(msg))
	

##########################################
def init(trace=False,debug=False):
	
	global log, logfileName, prog, ext
	
	coll_home = getCollHome()
	prog,ext = getProgramName()	
	#Load properties file in java.util.Properties
	propsFileName = coll_home+"/etc/collation.properties"
	inStream = FileInputStream(propsFileName)
	propFile = Properties()
	propFile.load(inStream) 
 
	log, logfileName = setupLog4jLogging(trace,debug)
	
	return log, logfileName, prog


#############################################################################
def getProgramName():
	global prog
	dirname, progname = os.path.split(sys.argv[0])	
	prog,ext = progname.split(".",1)
	return prog,ext


#############################################################################
def getCollHome():
	global coll_home
	coll_home = System.getProperty("com.collation.home")
	return coll_home
	

#############################################################################
def logit (level, message):  

	if level.upper() == "INFO":		
		#if string.upper(logLevel) in ["INFO","DEBUG","TRACE"]:
		log.info(message)
		if quiet != True:
			print level.upper() + ":	\t" +  message
			
	elif level.upper() in ["WARNING"]:			
		if logLevel.upper() in ["WARNING","ERROR","DEBUG","TRACE"]:
			log.info(message)		
			if  quiet != True:
				print level.upper() + ":\t" +  message
	
	elif level.upper() == "ERROR":			
		if logLevel.upper() in ["WARNING","ERROR","DEBUG","TRACE"]: 
			log.error(message)
			if  quiet != True:
				print level.upper() + ":\t" +  message

	elif level.upper() == "DEBUG":			
		if logLevel.upper() in ["DEBUG","TRACE"]:
			log.debug(message)
			if  quiet != True:
				print level.upper() + ":   \t" +  message
	
	return

		


#######################################################################
def setupLog4jLogging(trace=False,debug=False):
	global log, logLevel
	#coll_home = getCollHome()
	#prog,ext = getProgramName()
	#Load properties file in java.util.Properties
	propsFileName = coll_home+"/etc/collation.properties"
	inStream = FileInputStream(propsFileName)
	propFile = Properties()
	propFile.load(inStream) 
 

	if debug == True:
		logLevel = "DEBUG"
	else:
		logLevel = System.getProperty("com.collation.log.level")
	
	if logLevel == None:
		logLevel = "Info"

 
	# set properties for using the default TADDM log4j.xml file for logging
	if System.getProperty("com.collation.log.level") == None:
		System.setProperty("com.collation.log.level",propFile.getProperty("com.collation.log.level"))
	if System.getProperty("com.collation.log.filesize") == None:
		System.setProperty("com.collation.log.filesize",propFile.getProperty("com.collation.log.filesize"))
	if System.getProperty("com.collation.log.filecount") == None:
		System.setProperty("com.collation.log.filecount",propFile.getProperty("com.collation.log.filecount"))
	if System.getProperty("com.collation.log4j.servicename") == None:
		System.setProperty("com.collation.log4j.servicename","-" + prog)
			

	#Start logging
	
	# is a dedicated log4j.xml file provided (name is <prog>.xml
	log4jFile = []
	log4jFile.append("./"+prog+".xml")
	log4jFile.append(coll_home+"/etc/"+prog+".xml")
	log4jFile.append(coll_home+"/etc/log4j.xml")
	for logF in log4jFile: 
		if os.path.isfile(logF):
			log4j = logF
			break
	
	DOMConfigurator.configure(logF)
	log = Logger.getLogger("com.ibm.cdb.TivoliStdMsgLogger")

	layout = PatternLayout("%d{ISO8601} %X{service} [%t] %x %p %c{2} - %m\n")


	if logLevel == "INFO":
		log.setLevel(Level.INFO)
	elif logLevel == "ERROR":
		log.setLevel(Level.ERROR)
	elif logLevel == "DEBUG":
		log.setLevel(Level.DEBUG)
	elif logLevel == "TRACE":
		log.setLevel(Level.TRACE)
	
	logfile = File(coll_home+"/log/"+prog+".log")
	
	fileAppender = FileAppender(layout, logfile.getAbsolutePath(), True);
	
	log.addAppender(fileAppender);
	if trace == True:
		consoleAppender = ConsoleAppender(layout,"System.out")
		log.addAppender(consoleAppender);

	return log,logfile.getAbsolutePath()


###############################################################################
def executeScript(type):
	script = getScriptFileName(type)


	
	cmd = coll_home + os.sep + "bin" + os.sep + "dbupdate." 
	if "WINDOWS" in java.lang.System.getProperty("os.name").upper():
		cmd = cmd + "bat "
	else:	
		cmd = cmd + "sh "
	
	cmd = cmd + " -u " + taddmServerUser 
	cmd = cmd + " -p "  + taddmServerPassword  
	cmd = cmd + " -f " + getScriptFileName(type) 
	logit("INFO","executing:\t" +  cmd)
	##rc, output = commands.getstatusoutput(cmd + " " + args)
	
	p = Popen(cmd, shell=True, stdout=PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = p.communicate()
	rc = p.returncode
	
	logit("INFO","command return code:\t" + str(rc))
	logit("INFO","command output:\t" + str(stdout))
	logit("INFO","command error :\t" + str(stderr))


	
###############################################################################		
###   MAIN
###############################################################################

if 1==1:  #try:
	
	global log,logfileName,prog,ext,dirname,progname,coll_home,quiet, ext  
	log,logfileName,prog = init()	
	
	
	trace = False
	debug = False
	quiet = False
	argv = None
	
	
	taddmServerUser = "administrator"
	taddmServerPassword = "collation"
	#taddmServerHost = "localhost"
	#taddmServerPort = 9433
	
	coll_home = System.getProperty("com.collation.home")
	
	tableName = "ENUMERATIONS"
	viewName = "BB_ENUMERATIONS_V"
	indexName = "enum_field"
	scriptSuffix = "enumeration_table.sql"
	scriptLocation = coll_home + os.sep + "etc" + os.sep + "views" 
	
	####################################################################
	#	get arguments
	####################################################################
	action = None
	
	if len(sys.argv) == 1:
		raise Usage("help")
	if sys.argv[1].upper() == "HELP":
		raise Usage("help")
	elif not (sys.argv[1][0] == "-"):
		action = sys.argv[1]
		argv = sys.argv[2:]	
	else:
		argv = sys.argv[1:]
				
	shortOpts = "hqp:u:"
	longOpts = ["help","quiet","password=","user="]
			
	opts = {}
	args = {}
	
	try:		
		opts, args = getopt.getopt(argv, shortOpts, longOpts)
	except GetoptError, opt_ex:
		raise Usage(opt_ex.msg)	

	
	for o, a in opts:
		o = o.strip()
			
		if o in ("-h", "--help"):
			raise Usage("help")

		elif o in ("-q", "--quiet"):
			quiet = True
		
		elif o in ("-p", "--password"):
			taddmServerPassword = string.strip(a)

		elif o in ("-u", "--user"):
			taddmServerUser = string.strip(a)				

		else:
			raise Usage("You provided an unknown option: " + str(o))

	
		if len(args) > 0 and len(opts) > 0:
			
			a = string.strip(str(opts[len(opts) - 1]), "(")
			a = string.strip(a, ")")
			x, y = string.split(a, ",", 1)
			a = string.strip(x, "'") + " " + string.strip(y, "'")
			raise Exit(4, "Your input was not parsed correctly. The problem is likely related to the '" + str(args[0]) + "' argument number following '" + a + "'") 
	
	msg = None
	
	if action == None:
		msg = "No action specified"
	else:
		if action.upper() not in ["SCRIPTS","CREATE","REMOVE","HELP"] :
			msg = "Action not specified, or not one of 'create', 'remove, 'or 'script'"
	if taddmServerUser == None:
		msg = "\ttaddmServerUser (-u) must be specified."
	if taddmServerPassword == None:
		msg = "\ttaddmServerPassword (-p) must be specified."
	
	
	if msg != None:
		raise Usage(msg)
	


		
	if sys.argv[1].upper() == "CREATE":
		
		executeScript("create")

	elif sys.argv[1].upper() == "REMOVE":
		
		executeScript("drop")
		
	elif sys.argv[1].upper() == "SCRIPTS": 
		#############################
		#   get the enumerations
		#############################
		
		#  table layout
		#	ENUMERATION_NAME   NAME   TYPE  INTEGER
		
		enummerations = {}
		for name, obj in inspect.getmembers(enums):
			if inspect.isclass(obj):
				rows = [] 
				
				for f in obj.getDeclaredFields():
					#print str(obj.__name__) + "\tNAME:\t" + str(f.getName()) + "\tTYPE:\t" + str(f.getType().getSimpleName()) + " VALUE:" + str(f.getInt(f))
					
					row = [str(obj.__name__), f.getName(), str(f.getType().getSimpleName()), f.getInt(f)] 
					#row = "'" + str(obj.__name__) + "', '" + f.getName() + "', '" + str(f.getType().getSimpleName()) + "', " + f.getInt(f) 
					#print str(row)
					rows.append(row)
				
				enummerations[obj.__name__] = [obj, rows] 

		#databaseUser = System.getProperty("com.collation.db.user")
		
		
		##################################################
		#  create create and drop scripts 
		##################################################
		stmt = ""

		## drop view
		sql = "DROP view " + viewName
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 
		
		## drop table
		sql = "DROP table " +  tableName
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 

		# save output	
		saveFile(stmt,"drop")
		
		
		stmt = ""
		
		## create table		
		sql = "CREATE table " + tableName + " (ENUMERATION_NAME_X varchar(192), FIELD_NAME_X varchar(192), FIELD_TYPE_X varchar(16), FIELD_VALUE_X integer)"
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 

		
		## create view
		sql = "CREATE view " + viewName + " (ENUMERATION_NAME_C, FIELD_NAME_C, FIELD_TYPE_C, FIELD_VALUE_C)" 
		sql = sql + " as ( select ENUMERATION_NAME_X, FIELD_NAME_X, FIELD_TYPE_X, FIELD_VALUE_X from " + tableName + ")"
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 


		## create index
		sql = "CREATE unique index enum_field on " + tableName + " (ENUMERATION_NAME_X, FIELD_NAME_X)" 
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 


		## insert data
		logit("INFO","Getting ennumerations")		
		eKeys = enummerations.keys()
		eKeys.sort()
		num = 0
		for e in eKeys:
			logit("DEBUG","Reading enumeration " + str(e))		

			rows = enummerations[e][1]
			
			for r in rows:
				row = "'" + str(r[0]) + "', '" + str(r[1]) + "', '" + str(r[2]) + "', " + str(r[3])
				stmt = stmt + "\nINSERT INTO " + tableName + " VALUES(" + row +");"
					
		stmt = stmt + "\nCOMMIT;"
			
			

		
		sql = "GRANT SELECT ON " + tableName + " TO  PUBLIC"		   
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 
		
		sql = "GRANT SELECT ON " + viewName + " TO  PUBLIC"		   
		stmt = stmt + "\n" + sql + ";\nCOMMIT;" 

		saveFile(stmt,"create")	
		
		raise SystemExit(0)
			
'''	
except Quit, quit_ex:
	if quit_ex.rc == 0:
		log.info("\n" + prog + " ended  sucessfully")
	SystemExit()

except SystemExit,sys_ex:
	#print "---- " + str(sys_ex)
	sys.exit(sys_ex)


except Usage, usage_ex:				
	if not usage_ex.msg == "help":			 
		log.error("\nINVOCATION ERROR:\t" + usage_ex.msg) 
		print "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		print "\t" + usage_ex.msg
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
	show_help()			
	raise SystemExit(0)

except Exit, exit_ex:
	print exit_ex.msg 
	log.error("("+str(exit_ex.rc)+") " + exit_ex.msg)		
	raise SystemExit(exit_ex.rc)	

except Exception, ex:
	ex_type, ex, tb = sys.exc_info()    
	msg = str(ex_type) + ":\t" + str(ex) + "\n" + str(traceback.format_tb(tb)[0])
	logit("ERROR", msg) 
	sys.exit()
'''