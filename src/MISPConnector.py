'''
Created on Aug 20, 2016

This Script creates the MISP events from IoCs extracted from the APT reports and the analysis information of the malware hash.


@author: Andrew D. Kim (aka Daegeon Kim)
'''

from pymisp import api
from joblib.parallel import delayed
import datetime, joblib, requests, os, math
import MalwareRepositoryConnector as MRC
import main, LibIoC_DK

class MISPConnector(object):
    server = ''
    key = ''
    config = {}
    misp_connection = None
    malware_repo_connector = None
    ioc_stat = None
    parallel = None
        
    def __init__(self, config_value, _ioc_stat=None ):
        self.config = config_value
        self.server = config_value['MISP_URL']
        self.key = config_value['MISP_API_Key']
        self.initMISPConnection()
        self.createMalwareRepoConnector()
        self.ioc_stat = _ioc_stat
        #self.parallel = joblib.Parallel(joblib.cpu_count())
    
    
    def initMISPConnection(self):
        if self.misp_connection == None:
            self.misp_connection = api.PyMISP(self.server, self.key, False, 'json')
            
            
    def createMalwareRepoConnector(self):
        if self.malware_repo_connector == None:
            self.malware_repo_connector = MRC.MalwaresDotCom(self.config['Malware_Repository_API_Key'])
                
    
    ################################################################
    # check the existence of the MISP event created from the APT report.
    # @ input
    #    filename: the hash value representing the MISP event 
    # @ output
    #    return True if the MISP event exists.
    def checkMISPReportEventExist(self, filename):
        try:
            response = self.misp_connection.search_all(filename)
        except requests.exceptions.HTTPError:
            print '[checkMISPReportEventExist] HTTPError while querying '+filename
            return False
        if not response.has_key('response'):
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                return True
        return False
    
    
    ################################################################
    # check the existence of the MISP event created from the malware hash.
    # This function considers different representations of hashes, MD5, SHA1, and SHA256, to check the event existence.
    # @ input
    #    filename: the hash value representing the MISP event 
    # @ output
    #    return True if the MISP event of the malware hash exists in any types of hash representation of the hash.  
    def checkMISPHashEventExist(self, filename):
        try:
            response = self.misp_connection.search_all(filename)
        except requests.exceptions.HTTPError:
            print '[checkMISPHashEventExist] HTTPError while querying '+filename
            return False 
        
        if not response.has_key('response'):
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                return True
            for attr in r['Event']['Attribute']:
                if attr['category'] == 'Payload installation':
                    if attr['value'] == filename:
                        return True
        return False
    
    
    ################################################################
    # Create a MISP event from the list of IoCs in a report or in the analysis result of a malware hash.
    # This function considers different representations of hashes, MD5, SHA1, and SHA256, to check the event existence.
    # @ input
    #    val: the hash value representing the MISP event 
    #    filename: the filename of a APT report of a malware hash value
    #    _date: the publication of the APT reports
    # @ output
    #    return True if the MISP event is created.  
    def createMISPEvent(self, val, filename='', _date=''):
        if type(val)==str and LibIoC_DK.isHash(val):
            if self.createMISPEventFromHash(val, filename):
                self.ioc_stat.increaseAnalyzedHash()
                return True
        elif type(val)==list:
            if self.createMISPEventFromReport(val, filename, _date):
                self.ioc_stat.increaseNumberOfReport()
                return True
        return False
        
    
    ################################################################
    # Get the MISP event ID (eid) of filename as the event name.
    # @ input
    #    filename: the MISP event title to get the event ID (eid)
    # @ output
    #    return the eid if the event exists in the MISP, otherwise return False.
    def getMISPEventID(self, filename):
        try:
            response = self.misp_connection.search_all(filename)
        except requests.exceptions.HTTPError:
            print '[getMISPEventID] HTTPError while querying '+filename
            return False 
            
        if not response.has_key('response'):
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                return r['Event']['id']
        return False
        
    
    ################################################################
    # Get the report title where a MISP event is originated from.
    # @ input
    #    eid: the MISP event ID to get the origin report name
    #    event: the MISP event instance to get the origin report name
    # @ output
    #    return the event title and the originated report title if the eid or the event exists in MISP system.
    def getEventFileName(self, eid=None, event=None):
        if event == None:
            if eid == None:
                return False
            else:
                event = self.misp_connection.get(eid)
        else:
            event = self.misp_connection.get_event(event['Event']['id'])
            
        for attr in event['Event']['Attribute']:
            if attr['category'] == 'Other':
                return event['Event']['info'], attr['value']
        return False

    
    ################################################################
    # create the MISP event and append IoCs extra_hashcted from the APT report.
    # Is is impossible to extra_hashct the information that is hard to capture the patterns. e.g. name, mutex..
    # @ input
    #    ioc: the indicators of compromise list to be added in the MISP event of which format like (source, type, attribute)
    #    filename: the APT report file full path. This file name is used as the MISP event info.
    #     _date: the date that the APT report is published. This is used to set the date that the MISP event is created.
    # @ output
    #    Return True if the MISP event is created, otherwise return False.
    def createMISPEventFromReport(self, ioc, filename, _date):
        
        '''
        # if the MISP event for the filename already exists, add ioc in the event
        eid = self.getMISPEventID(filename[filename.rfind('\\')+1:])
        if eid:
            event = self.misp_connection.get_event(eid)
            for attr in ioc:
                self.addAttribute(event, attr)
            return False           
        '''
        if self.checkMISPReportEventExist(filename):
            return False
        
        if _date is not None:
            #_date = datetime.datetime.strptime(_date, "%m/%d/%Y").strftime("%Y-%m-%d")
            _date = _date.split("/");
            if int(_date[0]) > 12:
                _date = datetime.date(int(_date[0]),int(_date[1]),int(_date[2])).isoformat();
            else:
                _date = datetime.date(int(_date[2]),int(_date[0]),int(_date[1])).isoformat();
                
        event = self.misp_connection.new_event(0, 1, 2, filename[filename.rfind('\\')+1:], date=_date)
        self.misp_connection.add_named_attribute(event, 'Other', 'comment', filename[filename.rfind('\\')+1:])   # this will work as the ground truth of IoC
        
        if main._STAT_ and self.ioc_stat.report_name != filename:
            self.ioc_stat.setReportBuffer(filename)
        
        if main._PARALLELIZE_ATTRIB_ADDITION_:
            # Parallelized Version
            print '[Report] Parallelized attribute storing...'
            attr_added = joblib.Parallel(joblib.cpu_count())(delayed(addAttribute)(self, event, attr, filename) for attr in ioc)   
        else:
            # Sequential Version
            attr_added = False
            for attr in ioc:
                print '[Report] '+str(attr)
                attr_added = self.addAttribute(event, attr, filename) or attr_added
                
        if (type(attr_added) is bool and not attr_added):
            self.misp_connection.delete_event(event['Event']['id'])
            return False
        if type(attr_added) is list:
            if not(True in attr_added):
                self.misp_connection.delete_event(event['Event']['id'])
                return False
        
        return True
    
        
    ################################################################
    # Create the MISP event from the analysis result malware hash.
    # @ input
    #    _hash: the malware hash value to be analyzed and created MISP event.
    #    filename: the root filename where the hash value is originated.
    # @ output
    #    Return True if the MISP event is created, otherwise return False.
    def createMISPEventFromHash(self, _hash, filename, additional_hash=False):   
        # below string causes internal error of MISP system, so ignore such value     
        if '00000000000000000000000000000000' in _hash:
            return False
        
        _hash = _hash.lower()
        # if the MISP event for the hash value already exists, stop the further process.
        if self.checkMISPHashEventExist(_hash):
            return False
                
        result = self.malware_repo_connector.getMalwareInfo(_hash)
        if not result:
            return False
        
        '''
        # add timestamp of the hash file as the MISP event time
        sha256 = ''
        for attr in result:
            if attr[0].lower() == 'sha256':
                sha256 = attr[1]
                break        
        _date = self.malware_repo_connector.getMalwareCollectedDate(_hash)
        event = self.misp_connection.new_event(0, 1, 2, _hash, date = LibIoC_DK.getFileTimestamp(sha256))
        '''
        
        event = self.misp_connection.new_event(0, 1, 2, _hash)
        self.misp_connection.add_named_attribute(event, 'Other', 'comment', filename[filename.rfind('\\')+1:])   # this will work as the ground truth of IoCs      
        
        # the first three attributes in the result is md5, sha1, and sha256 representation malware hash, so manualy store them in the event.
        md5=result.pop(0)[2]
        sha1=result.pop(0)[2]
        sha256=result.pop(0)[2]
        if main._DOWNLOAD_MALWARE_:
            malware_buffer = self.malware_repo_connector.downloadMalware(sha256)
            if malware_buffer:
                f = open(_hash, 'w')
                f.write(malware_buffer)
                self.malware_repo_connector.unzipMalware(_hash)
    #            os.unlink(f.name)
                self.misp_connection.add_attachment(event, f, category='Payload installation')
                f.close()
        if not main._DOWNLOAD_MALWARE_ or not malware_buffer:
            self.misp_connection.add_hashes(event, category='Payload installation', md5=md5)
            if additional_hash:
                self.ioc_stat.addCategory2('hash')
            else:
                self.ioc_stat.addCategory3(_hash, 'hash')
            self.misp_connection.add_hashes(event, category='Payload installation', sha1=sha1)
            self.ioc_stat.addCategory2('hash')
            self.misp_connection.add_hashes(event, category='Payload installation', sha256=sha256)
            self.ioc_stat.addCategory2('hash')
        if main._STAT_ and self.ioc_stat.report_name != filename:
            self.ioc_stat.setReportBuffer(filename)
           
        attr_added = False
        if main._PARALLELIZE_ATTRIB_ADDITION_:
            # Parallelized Version
            print '[Hash] Parallelized attribute storing...'
            attr_added = joblib.Parallel(joblib.cpu_count())(delayed(addAttribute)(self, event, attr) for attr in result)   
            if (type(attr_added)==bool and not attr_added) or (type(attr_added)==list and not (True in attr_added)):
                self.misp_connection.delete_event(_hash)
                return False
        else:
            # Sequential Version
            attr_added = False
            for attr in result:
                print '[Hash] '+str(attr)
                attr_added = self.addAttribute(event, attr, filename) or attr_added

        return attr_added
            
            
    def addAttribute(self, event, attr, filepath):
        return addAttribute(self, event, attr, filepath)
        
        
    ################################################################
    # Download the malware information from mawares.com  and add them in the event.
    # @ input
    #    event: the MISP event handle that the malware information is stored.
    #    _hash: the malware hash value 
    # @ output
    #    Return True if any of malware static or behavior info is added in the MISP event.
    def addMalwareInfoFromRepository(self, event, _hash):
        return self.malware_repo_connector.getMalwareInfo(_hash, event, self)    
     
        
    ################################################################
    # Check if an attribute is stored in MISP system.
    # @ input
    #    attr: the attribute to check the existence in MISP
    #    eid: if eid is given, this function checks if the eid event contains the input attribute
    # @ output
    #    If eid is not given, the list of eid that contains the attribute is returned when the attribute is stored in MISP, 
    #    otherwise True or False is returned depending on whether the eid event containing the attribute.  
    def checkAttribute(self, attr, eid=None):
        if eid == None:
            try:
                response = self.misp_connection.search(attr)
            except requests.exceptions.HTTPError:
                print '[checkAttribute] HTTPError while searching '+attr
                return False 
                
            if response.has_key('response'):
                retval = []
                for e in response['response']:
                    found = False
                    for i in range(len(e['Event']['Attribute'])):
                        if e['Event']['Attribute'][i]['value'].encode('utf-8').lower() == attr.lower():
                            retval.append(e['Event']['id'])
                            found = True
                            break
                        if found:
                            break
                    if found:
                        break                    
                return retval
            else:
                return False
        else:
            if type(eid) != 'str':
                eid = str(eid)
            
            response = self.misp_connection.get(eid)
            if not response.has_key('Event'):
                return False
            
            if len(response) > 0 and len(response['Event']['Attribute']) > 0:
                for val in response['Event']['Attribute']:
                    for i in val:
                        if i['value'].encode('utf-8').lower() == attr.lower():
                            return True
        return False
    
    
    def exportXML(self, from_idx, to_idx, output_filename):
        import dicttoxml
        import xml.etree.ElementTree as ET
        root = ET.Element('response')
        for i in range(from_idx, to_idx):
            
            try:
                event = self.misp_connection.get_event(i)
            except:
                continue
            if 'message' in event and event['message'] == 'Invalid event.':
                continue
            xml = ET.fromstring( dicttoxml.dicttoxml(event) )
            root.append(xml.find('Event'))
        
        tree = ET.ElementTree(root)
        tree.write(output_filename)
        return
    
    
################################################################
# The collected attributes are stored to MISP through this function.
# The data filtering that checks redundancy and noise is applied within this function. 
def addAttribute(connector, event, attr, filepath):
    # if attr[0], the attribute type, is written in large character, the attr comes from the ioc parser,
    # otherwise from the malware repository. 
    attribute_info = attr[1].split('/')
    attribute_type = attribute_info[0].lower()
    if len(attribute_info) == 2:
        attribute_comment = attribute_info[1]
    else:
        attribute_comment = ''
    attr_lower_case = attr[2].lower()
    
    attribute_added = False
    event_name, source_name = connector.getEventFileName(event = event)
    event_name = event_name.encode('utf-8')
    source_name = source_name.encode('utf-8')
    

    # if the attribute is already stored in the MISP event, skip it
    tmp_id = connector.checkAttribute(attr=attr[2])
    sharedIoC = False
    if tmp_id:
        for curr_id in tmp_id:
            if str(event['Event']['id']) == curr_id:
                return False
            elif (LibIoC_DK.isHash(event_name) and not LibIoC_DK.isHash(connector.misp_connection.get_event(curr_id)['Event']['info'])) or (LibIoC_DK.isHash(connector.misp_connection.get_event(curr_id)['Event']['info'])) and not LibIoC_DK.isHash(event_name):
                connector.ioc_stat.addCategory3(attr_lower_case, connector.ioc_stat.convertIoCType(attribute_type))  # category 3
                sharedIoC = True
                break

    malwareAddedFromRepos = False
    if attr[0] == 'report' or attr[0] == 'static':
        attribute_category = 'External analysis'
    elif attr[0] == 'behavior':
        attribute_category = 'Artifacts dropped'
        
        
    if main._MODE_ == 1 or main._MODE_ == 3:
        if attribute_type == 'host':# or attribute_type == 'url':
            connector.misp_connection.add_url(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'ip' or attribute_type == 'src_ip':
            connector.misp_connection.add_ipsrc(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'dst_ip':
            connector.misp_connection.add_ipdst(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'email':
            connector.misp_connection.add_email_src(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'cve':
            connector.misp_connection.add_named_attribute(event, attribute_category, 'vulnerability', attr[2], comment=attribute_comment)
            attribute_added = True
#        elif attribute_type == 'registry':
#            connector.misp_connection.add_named_attribute(event, attribute_category, 'regkey', attr[2], comment=attribute_comment)
#            attribute_added = True
        elif attribute_type == 'filename':
            if LibIoC_DK.isFileofInterest(attr[2]):
                connector.misp_connection.add_named_attribute(event, attribute_category, 'filename', attr[2], comment=attribute_comment)
                attribute_added = True
#        elif attr[0] == 'Filepath':
#            connector.misp_connection.add_named_attribute(event, 'External analysis', 'text', attr[1], comment='file path')
#            attribute_added = True
        elif (attribute_type == 'pdb' or (attribute_type == 'filepath' and 'pdb' in attr[2])):
            connector.misp_connection.add_named_attribute(event, attribute_category, 'pdb', attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'signcheck':
            connector.misp_connection.add_named_attribute(event, attribute_category, 'text', attr[2], comment=attribute_comment)        
            attribute_added = True
                
        # If a malware hash is found, check if it is already stored in MISP as an attribute.
        # If MISP has already stored it, just add it as an attribute of the current event. 
        # Otherwise, create new MISP event if the analysis result could be found from malware repository.
        # If no the analysis result found from the repository, just add it as an attribute of the current event.
        elif attribute_type == 'md5' or attribute_type == 'sha1' or attribute_type == 'sha256':
            if not connector.checkAttribute(attr_lower_case):
                malwareAddedFromRepos = connector.createMISPEventFromHash(attr_lower_case, filepath)
                if malwareAddedFromRepos:
                    connector.ioc_stat.increaseAnalyzedAdditionalHash()
                                    
            if not malwareAddedFromRepos:
                if attribute_type == 'md5':
                    connector.misp_connection.add_hashes(event, category=attribute_category, md5=attr_lower_case, comment=attribute_comment)
                elif attribute_type == 'sha1':
                    connector.misp_connection.add_hashes(event, category=attribute_category, sha1=attr_lower_case, comment=attribute_comment)
                elif attribute_type == 'sha256':
                    connector.misp_connection.add_hashes(event, attribute_category, sha256=attr_lower_case, comment=attribute_comment)
                attribute_added = True
            
        elif attribute_type == 'string':
            connector.misp_connection.add_named_attribute(event, attribute_category, 'text', attr_lower_case, comment=attribute_comment)        
            attribute_added = True
                
    # IoC statistics calculation.
    if main._STAT_:
        if not sharedIoC:# and attribute_added:
            if LibIoC_DK.isHash(event_name):
                if attribute_added:
                    if connector.ioc_stat.checkIoCInReport(attr[2]):
                        connector.ioc_stat.addCategory2(connector.ioc_stat.convertIoCType(attribute_type)) # category 2
                    else:       
                        connector.ioc_stat.addCategory4(connector.ioc_stat.convertIoCType(attribute_type))  # category 4
            else:
                if attribute_added:
                    connector.ioc_stat.addCategory1(connector.ioc_stat.convertIoCType(attribute_type)) # category 1
                else:
                    connector.ioc_stat.addcategory5(connector.ioc_stat.convertIoCType(attribute_type)) # category 5
            
    return attribute_added




if __name__ == '__main__':
    # Load configuration file
    config_value = main.getConfig(main.config_file)
    file_names = main.getFileName(config_value['ReportRoot'])
    misp = MISPConnector(config_value)
    junk_size = 1000
    from_idx = 1
    to_idx = 3416
    num_junk = int(math.ceil(float(to_idx-from_idx+1)/junk_size))
    for i in range(num_junk):
        junk_from = (i)*junk_size+1
        junk_to = (i+1)*junk_size
        if junk_to > to_idx:
            junk_to = to_idx
        filename = 'CTIDataset('+str(junk_from)+'-'+str(junk_to)+').xml'
        print 'Generating file...: '+filename
        misp.exportXML(junk_from, junk_to, filename)
        print ' Done!'
