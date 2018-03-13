import sys
import zipfile
import shutil
import subprocess
import os
import re
import traceback
import json
import hashlib
from io import StringIO

import mmap
import struct

class Dexparser:

	def __init__(self, filedir):
		f = open(filedir, 'rb')
		m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

		self.mmap = m

		magic           = m[0:8]
		checksum        = struct.unpack('<L', m[8:0xC])[0]
		sa1             = m[0xC:0x20]
		file_size       = struct.unpack('<L', m[0x20:0x24])[0]
		header_size     = struct.unpack('<L', m[0x24:0x28])[0]
		endian_tag      = struct.unpack('<L', m[0x28:0x2C])[0]
		link_size       = struct.unpack('<L', m[0x2C:0x30])[0]
		link_off        = struct.unpack('<L', m[0x30:0x34])[0]
		map_off         = struct.unpack('<L', m[0x34:0x38])[0]
		string_ids_size = struct.unpack('<L', m[0x38:0x3C])[0]		
		string_ids_off  = struct.unpack('<L', m[0x3C:0x40])[0]
		type_ids_size   = struct.unpack('<L', m[0x40:0x44])[0]
		type_ids_off    = struct.unpack('<L', m[0x44:0x48])[0]
		proto_ids_size  = struct.unpack('<L', m[0x48:0x4C])[0]
		proto_ids_off   = struct.unpack('<L', m[0x4C:0x50])[0]
		field_ids_size  = struct.unpack('<L', m[0x50:0x54])[0]
		field_ids_off   = struct.unpack('<L', m[0x54:0x58])[0]
		method_ids_size = struct.unpack('<L', m[0x58:0x5C])[0]
		method_ids_off  = struct.unpack('<L', m[0x5C:0x60])[0]
		class_defs_size = struct.unpack('<L', m[0x60:0x64])[0]
		class_defs_off  = struct.unpack('<L', m[0x64:0x68])[0]
		data_size       = struct.unpack('<L', m[0x68:0x6C])[0]
		data_off		= struct.unpack('<L', m[0x6C:0x70])[0]

		hdr = {}
		
		hdr['magic'          ] = magic
		hdr['checksum'       ] = checksum
		hdr['sa1'            ] = sa1
		hdr['file_size'      ] = file_size
		hdr['header_size'    ] = header_size
		hdr['endian_tag'     ] = endian_tag
		hdr['link_size'      ] = link_size
		hdr['link_off'       ] = link_off
		hdr['map_off'        ] = map_off
		hdr['string_ids_size'] = string_ids_size
		hdr['string_ids_off' ] = string_ids_off
		hdr['type_ids_size'  ] = type_ids_size
		hdr['type_ids_off'   ] = type_ids_off
		hdr['proto_ids_size' ] = proto_ids_size
		hdr['proto_ids_off'  ] = proto_ids_off
		hdr['field_ids_size' ] = field_ids_size
		hdr['field_ids_off'  ] = field_ids_off
		hdr['method_ids_size'] = method_ids_size
		hdr['method_ids_off' ] = method_ids_off
		hdr['class_defs_size'] = class_defs_size
		hdr['class_defs_off' ] = class_defs_off
		hdr['data_size'      ] = data_size
		hdr['data_off'       ] = data_off
		
		self.header = hdr

	def checksum(self):
		return "%x" %self.header['checksum']

	def string_list(self):
		string_data = []

		string_ids_size = self.header['string_ids_size']
		string_ids_off  = self.header['string_ids_off']

		for i in range(string_ids_size):
			off = struct.unpack('<L', self.mmap[string_ids_off + (i*4) : string_ids_off + (i*4) + 4 ])[0]
			c_size = self.mmap[off]
			c_char = self.mmap[off+1:off+1+c_size]
			string_data.append(c_char)

		self.string_data = string_data #for method_id_list
		return string_data


	def typeid_list(self):
		type_data = []
		type_ids_size = self.header['type_ids_size']
		type_ids_off  = self.header['type_ids_off']

		for i in range(type_ids_size):
			idx = struct.unpack('<L', self.mmap[type_ids_off + (i*4) : type_ids_off + (i*4) + 4])[0]
			type_data.append(idx)

		self.type_data = type_data
		return type_data

	def method_list(self):
		method_data = []

		method_ids_size = self.header['method_ids_size']
		method_ids_off  = self.header['method_ids_off']

		for i in range(method_ids_size):
			class_idx = struct.unpack('<H', self.mmap[method_ids_off+(i*8)  :method_ids_off+(i*8)+2])[0]
			proto_idx = struct.unpack('<H', self.mmap[method_ids_off+(i*8)+2:method_ids_off+(i*8)+4])[0]
			name_idx  = struct.unpack('<L', self.mmap[method_ids_off+(i*8)+4:method_ids_off+(i*8)+8])[0]
			method_data.append([class_idx, proto_idx, name_idx])

		return method_data

	def __del__(self):
		pass

dexList = [] #dexfile list

#program usage
def usage():
	print ("androtools : no file specified")
	print ("./androtools <APK_FILE>")


#program information
def about(apkfile):
	print ("Target APK Path : %s" %apkfile)


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
def filehash(file,hash_method='md5'):
	hasher = getattr(hashlib,hash_method)()
	buf =  file.read(65536)
	while len(buf) > 0:
		hasher.update(buf)
		buf = file.read(65536)
	return hasher.hexdigest()


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
	infocmd = "aapt dump badging %s | findstr uses-permission > per_m.txt" %apkfile # in linux using 'grep'
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
	##subprocess.call("rm -r per_m.txt",shell=True)del /f 
	subprocess.call("del /f per_m.txt",shell=True)
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
#	print (stringlist)
	for i in range(len(stringlist)):
		email 	= re.findall(b'([\w.-]+)@([\w.-]+)', stringlist[i])
		url 	= re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', stringlist[i])
		ip 	= re.findall(b'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', stringlist[i])
		phone = re.findall(b'\d{2,3}-\d{3,4}-\d{3,4}',stringlist[i])
#		user_id	= re.findall(b'%(id)%',stringlist[i])

		if email:
			dexstrlist.append(str(email[0][0] + "@" + email[0][1]))
			emaillist += str(email[0][0] + "@" + email[0][1]).replace("b'", '')
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


	print ("######################## _Classes.dex_ File Artifects list ##########################")
#	print (dexstrlist)
	print ("print email list : %s" %emaillist)
	print ("print url list : %s" %urllist)
	print ("print ip list : %s" %iplist)
	print ("print phone list : %s" %phonelist)

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
	print (filterList)
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

	nativeparser(solist)

#Parsing Icon file
def parse_icon(apkfile):

	print ("############### Parsing IconFile ###############")

	iconfile_name = ""
	if not os.path.isdir('./pp_icon'):
		subprocess.call("mkdir pp_icon",shell=True)
	else:
		##subprocess.call("rm -r pp_icon",shell=True)
		subprocess.call("del /f pp_icon",shell=True)
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


	##subprocess.call("rm -rf pp_icon",shell=True)
	subprocess.call("rmdir /q pp_icon",shell=True)


#delete temp file directory
def delTemp():
	subprocess.call("rmdir /q temp",shell=True)
	##subprocess.call("rm -rf temp",shell=True)


#logging error to error_log.txt
def logError(error_msg):
	f = open('error_log.txt', 'a+')
	f.write('[*] ' + error_msg + '\n')
	f.close()

def main(apkfile):

	try:
		about(apkfile) #program information
		isVaild = zipfile.is_zipfile(apkfile) #check vaild zip container
		if isVaild:
			zfile = zipfile.ZipFile(apkfile)
			isAndroid = is_android(zfile) #check vaild android apk file
			if isAndroid:
				print ("[*] Analysis start!")

				
				extractDEX(zfile) #extract dex file

				permission = getManifest(apkfile)

#				parseDEX()
				suspicious_list_dex = parseDEX(apkfile)

				suspicious_list_native = nativefile(zfile)

				#parse_icon(apkfile)					

##				print(permission)
##				print(suspicious_list_dex)
##				print(suspicious_list_native)
				print((permission,suspicious_list_dex,suspicious_list_native))

				#extractString(report, apkfile)


			else:
				print ("[*] Sorry, We can\'t analyze this file")
		else:
			print ("[*] Sorry, We can\'t analyze this file")
		delTemp()
		print ("[*] Analysis complete!")
	except Exception as e:
		logError(str(traceback.format_exc()))
		print ("[*] Androtools Exception - Error logged!")
