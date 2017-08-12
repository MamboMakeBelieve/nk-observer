import os


while 1:
	i = 0
	#NK LOCAL SUBNET
	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'local nk subnet part 1/scan" + str(i) + ".xml' 175.45.176." + str(i)))
		os.system("python nmapdb.py --force-update -d  scans.db 'local nk subnet part 1/scan" + str(i) + ".xml'")

	i = 0

	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'local nk subnet part 2/scan" + str(i) + ".xml' 175.45.177." + str(i)))
		os.system("python nmapdb.py --force-update -d scans.db 'local nk subnet part 2/scan" + str(i) + ".xml'")

	i = 0

	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'local nk subnet part 3/scan" + str(i) + ".xml' 175.45.178." + str(i)))
		os.system("python nmapdb.py --force-update -d scans.db 'local nk subnet part 3/scan" + str(i) + ".xml'")

	i = 0

	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'local nk subnet part 4/scan" + str(i) + ".xml' 175.45.179." + str(i)))
		os.system("python nmapdb.py --force-update -d scans.db 'local nk subnet part 4/scan" + str(i) + ".xml'")
	i = 0
	#CHINESE UNICOM
	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'chn unicom/scan" + str(i) + ".xml' 210.52.109." + str(i)))
		os.system("python nmapdb.py --force-update -d scans.db 'chn unicom/scan" + str(i) + ".xml'")

	i = 0
	#SATGATE
	for i in range(256):
		os.system(str("sudo nmap -F -T4 -Pn -oX 'satgate/scan" + str(i) + ".xml' 77.94.35." + str(i)))
		os.system("python nmapdb.py --force-update -d scans.db 'satgate/scan" + str(i) + ".xml'")
