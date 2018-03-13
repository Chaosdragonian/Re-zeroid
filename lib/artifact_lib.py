import json,hashlib
import os
import datetime
import zipfile
import sys
import shutil
import subprocess
import os
import re
import traceback
from .dexparser import Dexparser

dexList = [] #dexfile list


def Empty_List(arg):
	if type(arg) == type(None):
		return []
	else:
		return arg


#check target file that this is vaild apk file
def is_android(zfile):
	for fname in zfile.namelist():
		if "AndroidManifest.xml" in fname:
			return True
		elif "resources.arsc" in fname:
			return True
		else:
			pass
	return False


#filehash extractor
def filehash(apkfile, mode):
	if mode == "md5":
		with open(apkfile, 'rb') as f:
			m = hashlib.md5()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha1":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha1()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha256":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha256()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()

	else:
		return ""


#extract dex file to temp file
def extractDEX(zfile):
	global dexList
	for fname in zfile.namelist():
		if fname[-4:] == ".dex": #if file extension is dex
			zfile.extract(fname, "temp")
			dexpath = os.path.join("temp", fname)
			dexhash = filehash(dexpath, "md5")
			print ("dexpath : %s" %dexpath)
			print ("dexhash : %s" %dexhash)
			shutil.move(dexpath, os.path.join("temp", dexhash + ".dex"))
			dexList.append(dexhash + ".dex")


def getManifest(apkfile):
	
	cmd = ""
	permission_list = ""

	print ("[*] Extracting Permission in AndroidManifest.xml File...")
	print ("############## Permission List in AndroidManifest.xml ##############")
	infocmd = "aapt dump badging %s | grep uses-permission > per_m.txt" %apkfile # in linux using 'grep'
	subprocess.call(infocmd,shell=True)
	f = open("./per_m.txt",'r')
	while True:
		line = f.readline()
		if not line: break
		line = line.split('\'')[-2]
		line = line.split('.')[-1]
		permission_list += line + ','
	f.close()
	print (permission_list)
	subprocess.call("rm -r per_m.txt",shell=True)
	return permission_list


#	cmd = "INSERT INTO ARTIFACT_INFO (PERMISSION_ARTIFACT) VALUES ()"
#	case_id = "qqqq"
#	member_id = "qqq"
#	cur.execute(cmd, (mysql_list, case_id, member_id))
#	cur.execute(cmd)
	
#find suspicious string in dex and replace if highlight
def findSuspicious(stringlist):
	dexstrlist = []
	emaillist = ""
	urllist = ""
	iplist = ""
	phonelist = ""
	right_emaillist = ("gmail","daum","naver","hotmail","hanmail")
#	print (stringlist)
	for i in range(len(stringlist)):
		email   = re.findall(b'([a-zA-Z0-9._-]+)@([a-zA-Z0-9]+)\.([a-zA-Z]+)', stringlist[i])
		url     = re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', stringlist[i])
		ip      = re.findall(b'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', stringlist[i])
		phone = re.findall(b'\d{2,3}-\d{3,4}-\d{3,4}',stringlist[i])
#		user_id	= re.findall(b'%(id)%',stringlist[i])
		if email:
			if (str(email[0][1]).replace("b'", '').replace("'", '')) in right_emaillist:
				print (email)
				dexstrlist.append(str(email[0][0]) + "@" + str(email[0][1]))
				emaillist += ((str(email[0][0]) + "@" + str(email[0][1]) + "." + str(email[0][2])).replace("b'", '')).replace("'", '') + "'"
			else:
				pass
		if url:
			dexstrlist.append(str(url[0]))
			if ((str(url[0]).replace("b'", '')).find("schemas.android.com")) >= 0:
				pass
			else:
				urllist += str(url[0]).replace("b'", '')
		if ip:
			dexstrlist.append(str(ip[0]))
			iplist += str(ip[0]).replace("b'", '')
		if phone:
			dexstrlist.append(str(phone[0]))
			phonelist += str(phone[0]).replace("b'", '')	


	#print ("######################## _Classes.dex_ File Artifects list ##########################")
#	print (dexstrlist)
	#print ("print email list : %s" %emaillist)
	#print ("print url list : %s" %urllist)
	#print ("print ip list : %s" %iplist)
	#print ("print phone list : %s" %phonelist)

	return [emaillist,urllist,iplist,phonelist]



def parseDEX(apkfile):
#def parseDEX(cur):
	global dexList

	suspicious_list,string = [],[]

	for dexfile in dexList:
		parse = Dexparser(os.path.join("temp", dexfile))
		tmp = parse.string_list()
		for t in tmp:
			string.append(bytes(t))
#		typeid = parse.typeid_list()
#		method = parse.method_list()
#		findSuspicious(string)
		suspicious_list.append(findSuspicious(string))
#		print (string)

	return suspicious_list

def nativeparser(solist):
	filterList = [[] for x in range(0,3)]
	for sofile in solist:
		with open(os.path.join("temp", sofile[1] + ".so"), 'rb') as f:
			data = str(f.read())
			email 	= re.findall(r'([\w.-]+)@([\w.-]+)', data)
			url 	= re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)
			ip 	= re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', data)

			if email:
				if str(email[0][0] + "@" + email[0][1]) not in filterList:
					filterList[0].append(str(email[0][0] + "@" + email[0][1]))
			if url:
				if str(url[0]) not in filterList:
					filterList[1].append(str(url[0]))
			if ip:
				if str(ip[0]) not in filterList:
					filterList[2].append(str(ip[0]))
	print ("######################## _.so_ File Artifects List ##########################")
	#print (filterList)
	return filterList


#native file information
def nativefile(zfile):
	print ("[*] Extracting Native File Data...")
	solist = []
	for fname in zfile.namelist():
		if fname[-3:] == ".so":
			tempArr = []
			sofile = os.path.basename(fname)
			source = zfile.open(fname)
			target = open(os.path.join("temp", sofile), "wb")
			with source, target:
				shutil.copyfileobj(source, target)
			sohash = filehash(os.path.join("temp", sofile), "sha1")
			shutil.move(os.path.join("temp", sofile), os.path.join("temp", sohash + ".so"))
			tempArr.append(fname)
			tempArr.append(sohash)
			solist.append(tempArr)

	result = nativeparser(solist)
	return result

#Parsing Icon file
def parse_icon(apkfile):

	print ("############### Parsing IconFile ###############")

	iconfile_name = ""
	if not os.path.isdir('./pp_icon'):
		subprocess.call("mkdir pp_icon",shell=True)
	else:
		subprocess.call("rm -r pp_icon",shell=True)
		subprocess.call("mkdir pp_icon",shell=True)
	cmd_line = "unzip -q %s -d pp_icon" %apkfile
	subprocess.call(cmd_line,shell=True)

	for (path,dir,files) in os.walk("./pp_icon/res/"):
		for filename in files:
			ext = os.path.splitext(filename)[-1]
			if path.find('drawable') >= 0:
				pass
			elif path.find('layout') >= 0:
				pass
			else:
				if filename == iconfile_name:
					pass
				else:
					if (ext == ".png" or ext == ".jpg"):
						if (filename.find("ic") >= 0):
							print (path + "/" + filename)
							subprocess.call("cp %s ./iconfile.png" %(path + "/" + filename),shell=True)
							iconfile_name = filename


	subprocess.call("rm -rf pp_icon",shell=True)
	shutil.rmtree('pp_icon')


#delete temp file directory
def delTemp():
	shutil.rmtree('temp')
	subprocess.call("rm -rf temp",shell=True)


#logging error to error_log.txt
def logError(error_msg):
	f = open('error_log.txt', 'a+')
	f.write('[*] ' + error_msg + '\n')
	f.close()
