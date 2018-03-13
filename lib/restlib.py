import os
import subprocess
import zipfile
import json
import time
import hashlib
import shutil

UPLOAD_PATH = "/home/karen/Upload"


def restlib_initalize(path):
	UPLOAD_PATH = path

#

def get_filehash(path,methods='sha1'):
	hasher = getattr(hashlib,methods)()
	file = open(path,'rb')
	buf =  file.read(65536)
	while len(buf) > 0:
		hasher.update(buf)
		buf = file.read(65536)
	return hasher.hexdigest()

#apk file의 이름과 CASE_NAME을 받아서 DEX를 추출하고 해당 경로들의 리스트를 반환..
def ExtractDEX(case_name,apkfile):
	DexList = []

	apkpath = os.path.join(UPLOAD_PATH,case_name,apkfile)
	zfile = zipfile.ZipFile(apkpath)
	for fname in zfile.namelist():
		if fname[-4:] == ".dex": #if file extension is dex
			zfile.extract(fname, os.path.join(UPLOAD_PATH,"DEX"))
			dexpath = os.path.join(UPLOAD_PATH,"DEX", fname)
			dexhash = get_filehash(dexpath, "md5")
			shutil.move(dexpath, os.path.join(UPLOAD_PATH,"DEX", dexhash + ".dex"))
			DexList.append(dexhash + ".dex")

	return DexList

# dex 파일의 이름을 입력하면 UPLOAD PATH에 JAR파일로 변환하여 
# 저장하고 해당 JAR 파일의 PATH를 돌려줌 
def dex2jar(dex_file):
	dex_path = os.path.join(UPLOAD_PATH,"DEX",dex_file)
	dex2jar = os.path.join(os.getcwd(),'lib' ,'delib','dex2jar', 'd2j-dex2jar.sh') # in linux modify .bat to .sh
	dex2jar_cmd = "{} {} {}".format('sh',dex2jar,dex_path) # in linux modify cmd to sh
	subprocess.call(dex2jar_cmd,shell=True)

	src_jar_path = os.path.join(dex_file[:-4] + '-dex2jar.jar')
	dst_jar_path = os.path.join(UPLOAD_PATH,"JAR",dex_file[:-4] + '-dex2jar.jar')
	print(src_jar_path,dst_jar_path)
	shutil.move(src_jar_path,dst_jar_path)

	return dst_jar_path

# JAR파일의 PATH 을 입력하면 압축을 해제하고 
# {source code folder name : { {package_name : [class_name 리스트, ... ]}, ... } } 들의 dictionary를 돌려줌.
# return package : classname
def get_classname(jar_file):
	ZIP = zipfile.ZipFile(jar_file,'r')
	fname = os.path.join(UPLOAD_PATH,jar_file) + '_class'
	print(fname)
	if os.path.isdir(fname)==False:
		ZIP.extractall(fname)

	table = {}
	names = ZIP.namelist()
	names = [x.split("/") for x in names if x.find('.class') != -1]

	for name in names:
		key,value = '.'.join(name[:len(name)-1]), name[len(name)-1]
		if key in table:
			table[key].append(value)
		else:
			table[key] = []
			table[key].append(value)
	ZIP.close()
	return table

def class2java(dex_name,package_name,classfile_name):
	classfile_path = os.path.join(UPLOAD_PATH,"JAR",dex_name + "-dex2jar.jar_class",\
		os.path.join(*package_name.split('.')),classfile_name)
	source_path = os.path.join(UPLOAD_PATH,"SOURCE",dex_name+'_source')
	jdax = os.path.join(os.getcwd(), 'lib' ,'delib','jadx','bin', 'jadx') # in linux remove .exe 
	jdax_cmd = "{} -d {} {}".format(jdax,source_path,classfile_path)
	subprocess.call(jdax_cmd,shell=True)

	name = classfile_name[:-6]+'.java'
	code = str(open(os.path.join(source_path,os.path.join(*package_name.split('.')),name),'r').read());
	return {name : code}

def class2cfg(dex_name,package_name,classfile_name):
	classfile_path = os.path.join(UPLOAD_PATH,"JAR",dex_name + "-dex2jar.jar_class",\
		os.path.join(*package_name.split('.')),classfile_name)
	cfg_path = os.path.join(UPLOAD_PATH,"GRAPH",dex_name)
	jdax = os.path.join(os.getcwd(), 'lib' ,'delib','jadx','bin', 'jadx') # in linux remove .exe 
	jdax_cmd = "{} --cfg -d {} {}".format(jdax,cfg_path,classfile_path)
	subprocess.call(jdax_cmd,shell=True)

	name = classfile_name[:-6]+'.dot'
	dot_file = str(open(os.path.join(source_path,os.path.join(*package_name.split('.')),name),'r').read());
	return {name : dot_file}
# jad execute function
# source_path 와 package name 과 classfile name을 입력하면 
# {classname : source } 를 돌려줌  # jad -o -sjava Size.class

#def class2java(dex_name,package_name,classfile_name): 
#	classfile_path = os.path.join(UPLOAD_PATH,"JAR",dex_name + "-dex2jar.jar_class",\
#		os.path.join(*package_name.split('.')),classfile_name)
#	source_path = os.path.join(UPLOAD_PATH,"SOURCE",dex_name+'_source')
#	jda = os.path.join(os.getcwd(), 'lib' ,'delib','jad', 'jad') # in linux remove .exe 
#	jda_cmd = "{} -o -d {} -sjava {}".format(jda,source_path,classfile_path)
#	subprocess.call(jda_cmd,shell=True)
#
#	name = classfile_name[:-6]+'.java'
#	#"<br />".join(mytext.split("\n"))
#	#code = "<br />".join(str(open(os.path.join(source_path,name),'rb').read()).split("\\r\\n"))[2:-1]
#	code = str(open(os.path.join(source_path,name),'r').read());
#	return {name : code}
	

#print(ExtractDEX('RZ-f94e487c-2016-0','AsaraTTA.apk'))
