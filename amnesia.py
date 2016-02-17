import threading
import os, re, sys
import subprocess
import argparse
import timeit

start_time = timeit.default_timer()
#dmp = "WIN7_dark.raw"
#os = "Win7SP0x64"
#kdbg = "0xf80003807110"

printlock = threading.Lock()
subprocess.call('mkdir raw', shell=True, stdout=subprocess.PIPE)

def error_message(filenm):
    fo = open("raw\\"+filenm+".txt", "w+")
    fo.write("Whoops! Something went really wrong here. You may want to run the plugin manually. ")
    fo.close()

def setup_profile(dmp):
	subprocess.Popen("..\\volatility-2.4\\vol.py -f ..\\%s imageinfo > raw\dump_info.txt" % dmp, shell=True, stdout=subprocess.PIPE).stdout.read()

	regex1 = re.compile(r"KDBG :\s(.*)[A-Z]")
	regex2 = re.compile(r"Profile\(s\) : ([^,]*).*")
	with open("raw\dump_info.txt") as f:
		for line in f:
			result = regex1.search(line)
			if result:
				kdbg_val = result.group(1)
	with open("raw\dump_info.txt") as f:
		for line in f:
			result = regex2.search(line)
			if result:
				os_profile = result.group(1)

	print "[+] Using Kernel Debugger Block: ", kdbg_val
	print "[+] Using OS profile: ", os_profile
	print

	return kdbg_val, os_profile

def processes(dmp, kdbg, os):
	try:
		with printlock:
			print "[-] PROCESSES: Enumerating processes using pool tag scanning"
		psscan_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s psscan > raw\psscan.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running PSSCAN module"
		error_message("psscan")

	try:
		with printlock:
			print "[-] PROCESSES: Walking the doubly-linked list pointed to by PsActiveProcessHead"
		pslist_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s pslist > raw\pslist.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running PSLIST module"
		error_message("pslist")

	#psxview_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s psxview > psxview.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	try:
		with printlock:
			print "[-] PROCESSES: Creating process list as parent/child tree"
		pstree_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s pstree > raw\pstree.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running PSTREE module"
		error_message("pstree")

	try:
		with printlock:
			print "[-] PROCESSES: Diffing processes found in EPROCESS and PsActiveProcessHead"
		pstree_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s psdiff > raw\hidden_processes.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running PSDIFF module"
		error_message("hidden_processes")

def malcode(dmp, kdbg, os):
	try:
		with printlock:
			print "[-] MALCODE: Extracting injected DLLs, injected code, unpacker stubs, API hook trampolines"
		subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s malfind > raw\malfind.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running MALFIND module"
		error_message("malfind")

	try:
		with printlock:
			print "[-] MALCODE: Looking for abnormal system processes"
		subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s malsysproc > raw\malsysproc.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running MALSYSPROC module"
		error_message("malsysproc")

	try:
		with printlock:
			print "[-] MALCODE: Searching unlinked DLLs by cross-referencing memory mapped files with the 3 PEB DLL lists"
		subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s ldrmodules > raw\unlinked_DLLs.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running LDRMODULES module"
		error_message("unlinked_DLLs")

def network(dmp, kdbg, os):
	try:
		with printlock:
			print "[-] NETWORK: Locating TCP endpoints, TCP listeners, UDP endpoints, and UDP listeners"
		netscan_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s netscan > raw\\network.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running network module"
		error_message("network")

def consoles(dmp, kdbg, os):
	try:
		with printlock:
			print "[-] CONSOLE: Scanning for console I/O information"
		netscan_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s consoles > raw\console_io.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running CONSOLES module"
		error_message("console_io")

	try:
		with printlock:
			print "[-] CONSOLE: Scanning for command shell inputs"
		netscan_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s cmdscan > raw\cmd.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running CMDSCAN module"
		error_message("cmd")

def rootkits(dmp, kdbg, os):
	try:
		#ssdt_ex - Kernel hooking
		with printlock:
			print "[-] ROOTKITS: Scanning for kernel hooking"
		ssdt_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s ssdt > raw\ssdt.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
		ssdt = open('raw\ssdt.txt', "r")
		for line in ssdt:
			if re.search(r'win32k', line) is None:
				if re.search(r'ntoskrnl', line) is None:
					f = open('raw\kernel_hooking.txt','a+')
					f.write(line)
	except:
		print "[!!] Error running SSDT module"
		error_message("ssdt")

	try:
		#apihooks [! TAKES TOO LONG !] - API inline/trampoline hooking - /score/rootkits_investigation_procedures.php
		#anidrivers - but really my plugin
		with printlock:
			print "[-] ROOTKITS: Scanning for suspicious kernel and system drivers"
		netscan_res = subprocess.Popen("..\\volatility-2.4\\vol.py --kdbg=%s --profile=%s -f ..\\%s maldrivers > raw\suspicious_drivers.txt" % (kdbg, os, dmp), shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		print "[!!] Error running MALDRIVERS module"
		error_message("suspicious_drivers")

##### MAIN ######
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Amnesia is a memory analysis tool")
	parser.add_argument("-f", help="This is the memory dump file to be analyzed", action="store_true")
	parser.add_argument("memdump_file", help="This is the memory dump file to be analyzed", type=str)

	args = parser.parse_args()
	dmp = args.memdump_file

	if args.memdump_file:
		print "[+] Analyzing memory dump: %s \n" % dmp
		kdbg, os = setup_profile(args.memdump_file)
		t1 = threading.Thread(target=processes, args=(dmp, kdbg, os))
		t2 = threading.Thread(target=malcode, args=(dmp, kdbg, os))
		t3 = threading.Thread(target=network, args=(dmp, kdbg, os))
		t4 = threading.Thread(target=consoles, args=(dmp, kdbg, os))
		t5 = threading.Thread(target=rootkits, args=(dmp, kdbg, os))

		#--- Start the threads
		t1.start()
		t2.start()
		t3.start()
		t4.start()
		t5.start()

		#--- Wait for all threads to finish
		t1.join()
		t2.join()
		t3.join()
		t4.join()
		t5.join()

		#--- ANY CLEAN UP REQUIRED
		subprocess.call('del raw\ssdt.txt', shell=True, stdout=subprocess.PIPE)
		subprocess.call('del raw\dump_info.txt', shell=True, stdout=subprocess.PIPE)

		#--- TIME OF EXECUTION
		seconds = round((timeit.default_timer() - start_time), 1)
		m, s = divmod(seconds, 60)
		print "[+] --- FINISHED: %02d minutes, %02d seconds ---" % (m, s)
	else:
		pass
