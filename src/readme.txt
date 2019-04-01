Contact information
- dgkim0803@{korea.ac.kr || hksecurity.net || gmail.com}

1. Requirements
	a. Data storage: MISP(http://www.misp-project.org/)
	b. Data storage API: pymisp(https://github.com/MISP/PyMISP) - provided in this project data as a package
	c. IoC extractor: ioc_parser(https://github.com/armbues/ioc_parser) - provided in this project data as a package
	d. Cyber threat report repository: APT reports(https://github.com/aptnotes/data)
	e. Malware repository: malwares.com API license(key)
	f. additional python libraries: xlrd, pdfminer, requests, joblib, dicttoxml, pefile (for data exporting)
	g. the configuration file including the root directory of reports, the file of report list, MISP server URL and the API key, and the malware repository key. 
	
2. This project is tested on below versions.
   a. MISP 2.4.56 + python 2.7 + malwares.com API v3
   b. MISP 2.4.105 + python 3.7 + malwares.com API v3

