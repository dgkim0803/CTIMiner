'''
Created on Aug 10, 2016
This is the main module for CTI_DBGenerator.
@author: Andrew D. Kim (aka Daegeon Kim)
'''
from iocp import Parser
from os.path import isfile, join
from joblib.parallel import delayed
import xml.etree.ElementTree as ET
import itertools, csv, hashlib, requests, os, joblib
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import MISPConnector, IoCStatistics

# 1 : parsing APT report only
# 2 : adding malware repository IoCs only
# 3 : full functionality mode(MODE 1 & 2)
_MODE_ = 3

# True : calculate statistical characteristics
_STAT_ = True

# 1 : generate MISP event in report-wise manner
# 2 : generate MISP event malwar-wise manner first and create the event of the report using the left-over attributes.
_MISP_EVENT_GENERATION_TYPE = 2

_COUNTER_LIMIT_ = 1
_DOWNLOAD_MALWARE_ = False
_PARALLELIZE_FILE_PROCESSING_ = False
_PARALLELIZE_ATTRIB_ADDITION_ = False

# the required system configuration should be set in the config file.
config_file = 'config_PC.xml'

if _STAT_:
    ioc_stat = IoCStatistics.IoCStatistics()

################################################################
# Get the configuration values from the configuration file.
# @inputs
#    config_file: the full path of the configuration file.
# @outputs
#    Returns the list of configuration values.
def getConfig(config_file):
    retval = {}
    tree = ET.parse(config_file)
    root = tree.getroot()
    
    for child in root:
        retval[child.tag] = child.text
    return retval

################################################################
# Get all APT report file names from the root directory.
# @inputs
#    root_dir: the root directory containing the APT reports.
# @outputs
#    Returns the list of the full path of the APT reports.
def getFileName(root_dir):  # need to be modified!!!!! filenames are checked twice!! exception is not applied on 'exception' folder!
    if 'exception' in root_dir:
        return
    retval = [];
    dir_list = os.listdir(root_dir)
    for d in dir_list:
        if 'exception' in d:
            continue
        tmp_name = join(root_dir,d)
        if isfile(tmp_name):
            retval.append(tmp_name)
        else:
            filename = getFileName(tmp_name)
            if filename is not None:
                retval = list(itertools.chain(retval, filename))
    
    return retval

################################################################
# Get parsed ioc value from the APT reports using ioc_parser.
# @ inputs
#    file_name: the APT report file name
# @ outputs
#    Returns the list of IoCs retrieved by the parser.
def parse_ioc(file_name):
    parser = None
    retval = None
    if '.pdf' in file_name:
        parser = Parser.Parser(None, 'pdf', True, 'pdfminer', 'json')
    elif '.xls' in file_name or '.xlsx' in file_name:
        parser = Parser.Parser(None, 'xls', True, 'requests', 'json')
    elif '.csv' in file_name:
        parser = Parser.Parser(None, 'csv', True, 'requests', 'json')
    else:
        parser = Parser.Parser(None, 'txt', True, 'requests', 'json')
    try:
        parser.parse(file_name)
        retval = parser.dedup_store
    except TypeError:
        retval = None 
    
    return retval

################################################################
# Get the release date of the APT report from the file listing APT reports.
# The path of the list file should be provided 'ReportList" key in the configuration file.
# @ inputs
#    filepath: the APT report file path
def getFileDate(filepath, config_value):
    filename = filepath[filepath.rfind('\\')+1:]
    if config_value.has_key('ReportList') == False:
        return
    else:
        f=open(config_value['ReportList'], 'rb')
        csv_reader = csv.reader(f, delimiter=',')
        for row in csv_reader:
            if row[0] in filename:
                return row[5]
            
            hasher = hashlib.sha1()
            with open(filepath, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
            if row[4] is not None and row[4]!="" and row[4] in hasher.hexdigest():
                return row[5]
    return
    
    
def processFile(misp, f, config_value):
    # Adding MISP by APT report-wise manner: one MISP event is consisted by one API report. 
    if _MISP_EVENT_GENERATION_TYPE == 1: 
        # check if the event data is already in MISP server 
        if misp.checkEventExist(f[f.rfind('\\')+1:]) == True:
            return
        print f[f.rfind('\\')+1:]
        # extract IoCs in the report file
        ioc = parse_ioc(f)
        if ioc is not None and len(ioc) > 0:
            date = getFileDate(f, config_value)
            misp.createMISPEvent(ioc, f, date)
            
            if _STAT_:
                ioc_stat.finalizeTempStatistics()
                ioc_stat.reset()
                ioc_stat.saveIoCStatistics()
        
    # Adding MISP by malware-wise manner. MISP events are consisted by each malware hashes in APT report
    # if further analysis results could be retrieved from malware repository, 
    # otherwise rest of IoCs are stored in one MISP event under the event name as the title of the report.
    elif _MISP_EVENT_GENERATION_TYPE == 2:
        if misp.checkMISPReportEventExist(f[f.rfind('\\')+1:]):
            return
        nonHash_IoC = []
        hash_IoC = []
        ioc = parse_ioc(f)
        if ioc is not None and len(ioc) > 0:
            for attr in ioc:
                # if the IoC is a hash value and the analysis result of the hash could be retrieved,
                # create a MISP event of the hash value 
                if attr[0] == 'MD5' or attr[0] == 'SHA1' or attr[0] == 'SHA256':
                    hash_IoC.append(('report',attr[0],attr[1]))
                    if _STAT_:
                        ioc_stat.increaseHashInReport()
                    
                # if the IoC is not a hash value or the analysis result of a hash could not be retrieved,
                # keep the IoC to store under the MISP event of the API report
                else:
                    nonHash_IoC.append(('report',attr[0],attr[1]))
        
            # add hash IoCs in each MISP events
            if (_MODE_==2 or _MODE_==3) and len(hash_IoC) > 0:
                for attr in hash_IoC:
                    if not misp.createMISPEvent(attr[2], f):
                        nonHash_IoC.append(attr)
                    elif _STAT_:
                        ioc_stat.increaseAnalyzedHash()
            
            # add non-hash IoCs in one MISP event
            if (_MODE_==1 or _MODE_==3) and len(nonHash_IoC) > 0:
                date = getFileDate(f, config_value)
                misp.createMISPEvent(nonHash_IoC, f, date)
                                     
            if _STAT_:
                ioc_stat.finalizeTempStatistics()
                ioc_stat.reset()
                ioc_stat.saveIoCStatistics()
    
    
def processFileList(misp, file_names, config_value):
    # Adding MISP by APT report-wise manner: one MISP event is consisted by one API report. 
    if _MISP_EVENT_GENERATION_TYPE == 1: 
        for f in file_names:
            # check if the event data is already in MISP server 
            if misp.checkEventExist(f[f.rfind('\\')+1:]) == True:
                continue
            print f[f.rfind('\\')+1:]
            # extract IoCs in the report file
            ioc = parse_ioc(f)
            if ioc is not None and len(ioc) > 0:
                date = getFileDate(f, config_value)
                misp.createMISPEvent(ioc, f, date)
                
                if _STAT_:
                    ioc_stat.finalizeTempStatistics()
                    ioc_stat.reset()
                    ioc_stat.saveIoCStatistics()
        
    # Adding MISP by malware-wise manner. MISP events are consisted by each malware hashes in APT report
    # if further analysis results could be retrieved from malware repository, 
    # otherwise rest of IoCs are stored in one MISP event under the event name as the title of the report.
    elif _MISP_EVENT_GENERATION_TYPE == 2:
        for f in file_names:
            if misp.checkMISPReportEventExist(f[f.rfind('\\')+1:]):
                continue
            nonHash_IoC = []
            hash_IoC = []
            ioc = parse_ioc(f)
            if ioc is not None and len(ioc) > 0:
                for attr in ioc:
                    # if the IoC is a hash value and the analysis result of the hash could be retrieved,
                    # create a MISP event of the hash value 
                    if attr[0] == 'MD5' or attr[0] == 'SHA1' or attr[0] == 'SHA256':
                        hash_IoC.append(('report',attr[0],attr[1]))
                        if _STAT_:
                            ioc_stat.increaseHashInReport()
                        
                    # if the IoC is not a hash value or the analysis result of a hash could not be retrieved,
                    # keep the IoC to store under the MISP event of the API report
                    else:
                        nonHash_IoC.append(('report',attr[0],attr[1]))
            
                # add hash IoCs in each MISP events
                if (_MODE_==2 or _MODE_==3) and len(hash_IoC) > 0:
                    for attr in hash_IoC:
                        if not misp.createMISPEvent(attr[2], f):
                            nonHash_IoC.append(attr)
                        elif _STAT_:
                            ioc_stat.increaseAnalyzedHash()
                
                # add non-hash IoCs in one MISP event
                if (_MODE_==1 or _MODE_==3) and len(nonHash_IoC) > 0:
                    date = getFileDate(f, config_value)
                    misp.createMISPEvent(nonHash_IoC, f, date)
                    
                if _STAT_:
                    ioc_stat.finalizeTempStatistics()
                    ioc_stat.reset()
                    ioc_stat.saveIoCStatistics()
                    
'''
 The main routine
'''
if __name__ == '__main__':
    
    # Load configuration file
    config_value = getConfig(config_file)
    file_names = getFileName(config_value['ReportRoot'])
    misp = MISPConnector.MISPConnector(config_value, ioc_stat)
    
    if _PARALLELIZE_FILE_PROCESSING_:
        joblib.Parallel(joblib.cpu_count())(delayed(processFile)(misp, f, config_value) for f in file_names)
    else:
        processFileList(misp, file_names, config_value)
    