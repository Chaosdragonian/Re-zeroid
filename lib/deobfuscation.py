import sys
import subprocess
import os
import signal

# /home/karen/Desktop/deobfuscator/bin/deobfuscator --help
# /home/karen/Application/lib/delib/bin

class Alarm(Exception):
	pass

def alarm_handler(signum,frame):
	raise Alarm

# apkfile : APK's path
def deobfuscate(apkfile):

	signal.signal(signal.SIGALRM,alarm_handler)
	signal.alarm(10*60)

	pathenv = os.environ.copy()
	pathenv["PATH"] = "/home/karen/Application/lib/delib/bin:" + pathenv["PATH"]

	deobfuscator_path = '/' + os.path.join('home','karen','Desktop' ,'deobfuscator','bin','deobfuscator')
	cmd = [deobfuscator_path,apkfile]
	proc = subprocess.Popen(cmd,stdout=subprocess.PIPE, env=pathenv)

	try:
		output_str = proc.communicate()[0]
		tmp = str(os.path.basename(apkfile))[2:-1]
		apk_filename = tmp[:-4] + '_rezeroid.apk'
		print(apk_filename)
		apk_path = os.path.join(os.getcwd(),apk_filename)
		print(apk_path)
		signal.alarm(0)
	except Alarm:
		output_str = 'timeout_error'
		apk_path = 'timeout_error'

	return (str(output_str),str(apk_path))


#output = deobfuscate("/home/karen/Obad.A.apk")
#print(output[0])
#print(output[1])