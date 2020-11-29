The simple programm to control list of files with hash-function.
Requirements: confirparser, time, pathlib, hashlib, rsa, os, pymysql, sqlite3

Programm can be run in two basic modes:
		init - create list of files to control and save it hashes in file or db
		check - create list of files and compare it with hashes in file or db
		if empty the python shell will be run
With 'MAIN' section:
	You can choose hash type with 'hash' option but it should be in hashlib.
	The programm will store hash-values in 'service_folder'. Remember that you need to store hash-values in secret. Malefactor can replace the hash-value of 		file!
	The 'control_point' option setup the time of last initialization. You can switch between copy by replacing this value with timestamp of new point. You can 	find the timestamps in service folder.

With 'DB' section you can setup the database settings. If MySQL is choosen, you need to create db and grant privileges on it before initialization!
Remeber! Store password in configs is not secure! Set 0 or leave empty to save hash-values in file.

With 'CRYPTO' section you can choose hash-function to use. Also here you can provide path to your RSA keys. PVKey will be used in initialization to creat control point. PBKey will be used to verify files integrity in check mode.

With 'FILE_LIST' section you can set the list of files that should be controlled. You have three options for this:
	dir_check_all - setup path to control all files in this dir and all subdirs one perline
	dir_check_filtr - setup path and filter to control specific files in dir
		EXAMPLE!
		#dir_check_filtr = /var/
		#				/etc/
		#
		#filtr = *.pcap, *.log, *.exe
		#		*.md	
	dir_check_files - setup path to control all files in this dir without subdirs	

programm structure: 
		fmanager.py - default programm provide control of running process
		fim.py - provide methods to create list of files, hash-values and work with DB

