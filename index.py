from flask import *
from flaskext.mysql import MySQL
from flask.ext.hashing import Hashing
from werkzeug import secure_filename
from flask_cors import CORS, cross_origin
import json,hashlib
import os
import datetime
import zipfile
import sys
import os
import re
import shutil

from lib.artifact_lib import *
from lib.restlib import *
from lib.deobfuscation import *


app = Flask(__name__)
mysql = MySQL();
hashing = Hashing(app)
CORS(app)

DB_SALT = "r3md415uk1!@#$".encode('utf-8')
COMMON_SALT = "3m1l14d415uk1!@#$".encode('utf-8')

UPLOAD_FOLDER = "/home/karen/Upload".encode('utf-8')
ALLOWED_EXTENSIONS = set(['apk'.encode('utf-8')])

app.secret_key = hashlib.sha224(COMMON_SALT).hexdigest()

app.config['MYSQL_DATABASE_USER'] = 'root2'
app.config['MYSQL_DATABASE_PASSWORD'] = 'keroro2424.'
app.config['MYSQL_DATABASE_DB'] = 'rezeroid'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

mysql.init_app(app)

# M_CODE = HASH(M_ID + M_PW + SALT)

def apk_check(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].encode('utf-8') in ALLOWED_EXTENSIONS

def counting_case():
	cursor = mysql.get_db().cursor()
	cursor.execute("SELECT COUNT(*) FROM case_info ")
	return cursor.fetchone()[0]

def make_casename(m_code):
	return 'RZ-' + m_code + '-' + str(datetime.datetime.now().year) + '-' + str(counting_case())

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login',methods=['POST'])
def login():
	if request.method == 'POST' : 
		user_id = request.form['userid']
		user_pw = hashing.hash_value(request.form['userpass'], salt=DB_SALT)

		cursor = mysql.get_db().cursor()
		cursor.execute("SELECT M_ID FROM member WHERE M_MAIL = '{}' AND M_PW = '{}'".format(user_id,user_pw))

		rows = cursor.fetchall()

		if (len(rows) > 0):
			session['userid'] = request.form['userid']
			return render_template('index.html')
		else:
			print("login failed")
			return render_template('index.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('userid', None)
    return redirect(url_for('index'))

@app.route('/upload',methods=['GET','POST'])
def upload():

	# 1. check if uploaded_file is APK or not 
	if request.method == 'POST' and apk_check(request.files["file"].filename):
		cursor = mysql.get_db().cursor()

		file = request.files["file"]

		# 2. 폴더 만들기. (Folder NAMING : RZ-case#-year-num (num is enumerating with COUNT(CASE_INFO)))

		if 'userid' in session:
			cursor.execute("SELECT M_CODE FROM member WHERE M_MAIL = '{}'".format(session['userid']))
			m_code = cursor.fetchall()[0][0]
		else:
			m_code = hashing.hash_value('JohnDoe', salt=COMMON_SALT)[0:8]

		case_name = make_casename(m_code)
		folder_name = os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(case_name).encode('utf-8'))
		if not os.path.isdir(folder_name):
			os.mkdir(folder_name)

		# 3. 파일이름 Naming
		filename = os.path.join(folder_name, secure_filename(file.filename).encode('utf-8'))

		# 4. Upload 파일 Save
		file.save(filename.decode('utf-8'))
		file.seek(0)
		md5_hash = hashlib.md5(file.read()).hexdigest() 
		file.seek(0)
		sha1_hash = hashlib.sha1(file.read()).hexdigest()

		# deobfuscator routine

		message,apkpath_deobfuscated = deobfuscate(filename)

		if message != 'timeout_error':
			apk_name = os.path.basename(apkpath_deobfuscated)
			dst_apkpath_deobfuscated = os.path.join(folder_name.decode('utf-8'),apk_name)
			print(dst_apkpath_deobfuscated)
			print(apkpath_deobfuscated)
			shutil.move(apkpath_deobfuscated, dst_apkpath_deobfuscated)
			apk_size = os.path.getsize(dst_apkpath_deobfuscated)
		else:
			apk_name = request.files["file"].filename
			apk_size = request.content_length

		# 5. Case list, Case info, APK info 저장
		cursor.execute("INSERT INTO case_list (M_CODE, CASE_ID) VALUES ('{}','{}')".format(m_code,case_name))
		mysql.get_db().commit()

		cursor.execute("INSERT INTO case_info (CASE_ID, ARTIFACT_ID) VALUES ('{}','{}')".format(case_name,case_name))
		mysql.get_db().commit()

		cursor.execute("INSERT INTO apk_info (CASE_ID, APK_NAME, APK_SIZE, APK_HASH_MD5, APK_HASH_SHA1) VALUES ('{}','{}','{}','{}','{}')".format(case_name,apk_name,apk_size,md5_hash,sha1_hash))
		mysql.get_db().commit()

		session['casename'] = case_name
		dexList[:] = []

		return redirect(url_for('index'))
	else:
		return 'File upload Failed'

@app.route('/history')
def history():
	return 'history page'

@app.route('/artifact/<casename>',methods=['GET'])
def artifact(casename):

	cursor = mysql.get_db().cursor()

	cursor.execute("SELECT * FROM apk_info WHERE CASE_ID = '{}'".format(casename))
	tmp = cursor.fetchone()

	if tmp == None:
		return 'not found file...'

	print(tmp)

	apk_info = {}
	i = 1
	for k in ['apkname','apksize','md5','sha1']:
		apk_info[k] = tmp[i]
		i = i + 1

	cursor.execute("SELECT * FROM artifact_info WHERE ARTIFACT_ID = '{}'".format(casename))
	artifact_info = cursor.fetchone()

	if artifact_info != None:
		artifact_dict = {}
		i = 0
		for k in ['casename','permission','domain','email','ip','phone']:
			if k != 'permission':
				artifact_dict[k] = artifact_info[i].split('|')
			else:
				artifact_dict[k] = artifact_info[i].split(',')
			i = i + 1

		for k in ['apkname','apksize','md5','sha1']:
			artifact_dict[k] = apk_info[k]
		print(artifact_dict)

		return json.dumps(artifact_dict)
		#(ARTIFACT_ID, PERMISSION_ARTIFACT, DOMAIN_ARTIFACT, MAIL_ARTIFACT, ADDRESS_ARTIFACT, PHONE_ARTIFACT)
	else:
		cursor.execute("SELECT APK_NAME FROM apk_info WHERE CASE_ID = '{}'".format(casename))
		folder_name = os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(casename).encode('utf-8'))

		tmp = cursor.fetchone()[0]
		print(tmp)

		filename = os.path.join(folder_name, secure_filename(tmp).encode('utf-8'))
		filename = str(filename)[2:].split('\'')[0]
		isVaild = zipfile.is_zipfile(filename) #check vaild zip container
		if isVaild:
			zfile = zipfile.ZipFile(str(filename))
			isAndroid = is_android(zfile) #check vaild android apk file
			if isAndroid:
				extractDEX(zfile) #extract dex file

				permission = getManifest(filename)
				suspicious_list_dex,suspicious_list_native = [],[]

				for x in parseDEX(filename):
					suspicious_list_dex = suspicious_list_dex + x

				email,url,ip,phone = '','','',''

				if suspicious_list_dex != None:
					i = 0
					while i < len(suspicious_list_dex)/4:
						email = email + suspicious_list_dex[4*i]
						url = url + suspicious_list_dex[4*i + 1]
						ip = ip + suspicious_list_dex[4*i + 2]
						phone = phone + suspicious_list_dex[4*i + 3]
						i = i + 1

				email,url,ip,phone = email.replace('\'','|'),url.replace('\'','|'),ip.replace('\'','|'),phone.replace('\'','|')

				print("INSERT INTO artifact_info (CASE_ID, PERMISSION_ARTIFACT, DOMAIN_ARTIFACT, MAIL_ARTIFACT, ADDRESS_ARTIFACT, PHONE_ARTIFACT) VALUES ('{}','{}','{}','{}','{}','{}')".format(casename,permission,url,email,ip,phone))

				cursor = mysql.get_db().cursor()
				cursor.execute("INSERT INTO artifact_info (ARTIFACT_ID, PERMISSION_ARTIFACT, DOMAIN_ARTIFACT, MAIL_ARTIFACT, ADDRESS_ARTIFACT, PHONE_ARTIFACT) VALUES ('{}','{}','{}','{}','{}','{}')".format(casename,permission,url,email,ip,phone))
				mysql.get_db().commit()

				artifact_dict = {} # ['casename','permission','domain','email','ip','phone']:
				artifact_dict['casename'] = casename.split('|')
				artifact_dict['permission'] = permission.split(',')
				artifact_dict['domain'] = url.split('|')
				artifact_dict['email'] = email.split('|')
				artifact_dict['ip'] = ip.split('|')
				artifact_dict['phone'] = phone.split('|')
				for k in ['apkname','apksize','md5','sha1']:
					artifact_dict[k] = apk_info[k]
				return json.dumps(artifact_dict)
	return 'error'

@app.route('/codenametable/<casename>',methods=['GET'])
def codenametable(casename):


	cursor = mysql.get_db().cursor()
	cursor.execute("SELECT APK_NAME FROM apk_info WHERE CASE_ID = '{}'".format(casename))
	apkname = cursor.fetchone()
	print(apkname)

	if apkname==None:
		return 'failed'

	name_tables = {}

	apkname = apkname[0]

	dex_list = ExtractDEX(casename,apkname)
	print(dex_list)

	for dexname in dex_list:
		jar_path = dex2jar(dexname)
		name_tables[dexname] = get_classname(jar_path)

	return json.dumps(name_tables)

@app.route('/code/<dex>/<package>/<classfile>',methods=['GET'])
def code(dex,package,classfile):

	data = class2java(dex[:-4],package,classfile)
	#print(data)

	return json.dumps(data)

@app.route('/report/<casename>',methods=['GET'])
def report(casename):
	return render_template('report.html',casename=casename)

@app.route('/register',methods=['POST'])
def register():
	if request.method == 'POST':
		conn = mysql.get_db()
		cursor = conn.cursor()

		user_id = request.form['userid']
		user_pw = hashing.hash_value(request.form['userpass'], salt=DB_SALT)
		user_code = hashing.hash_value(request.form['userid'] + request.form['userpass'], salt=DB_SALT)[0:8]

		cursor.execute("SELECT M_MAIL FROM member WHERE M_MAIL = '{}'".format(user_id))
		rows = cursor.fetchall()
		if (len(rows) > 0):
			return redirect(url_for('index'))
		
		cursor.execute("INSERT INTO member (M_MAIL, M_PW, M_CODE) VALUES ('{}','{}','{}')".format(user_id,user_pw,user_code))
		conn.commit()

		return redirect(url_for('index'))

if __name__ == '__main__':
	app.run(host='0.0.0.0',port=30000)