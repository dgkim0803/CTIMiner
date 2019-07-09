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
            LibIoC_DK.debugging("Checking the MISP file event existence: %s" %(filename), main._DEBUG_, main._LOGGING_, main.hFile) 
            response = self.misp_connection.search_all(filename)
        except requests.exceptions.HTTPError:
            LibIoC_DK.debugging("HTTPError while querying "+filename, main._DEBUG_, main._LOGGING_, main.hFile) 
            return False
        if (main.is_py2 and not response.has_key('response')) or (main.is_py3 and 'response' not in response):
            LibIoC_DK.debugging("The MISP file event NOT exist", main._DEBUG_, main._LOGGING_, main.hFile)
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                LibIoC_DK.debugging("The MISP file event ALREADY exists", main._DEBUG_, main._LOGGING_, main.hFile)
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
            LibIoC_DK.debugging("Checking the MISP hash event existence: %s" %(filename), main._DEBUG_, main._LOGGING_, main.hFile)
            response = self.misp_connection.search_all(filename)
        except requests.exceptions.HTTPError:
            LibIoC_DK.debugging("HTTPError occurred", main._DEBUG_, main._LOGGING_, main.hFile)
            return False 
        if (main.is_py2 and not response.has_key('response')) or (main.is_py3 and 'response' not in response):
        #if not response.has_key('response'):
            LibIoC_DK.debugging("The MISP hash event NOT exist", main._DEBUG_, main._LOGGING_, main.hFile)
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                LibIoC_DK.debugging("The MISP hash event ALREADY exists", main._DEBUG_, main._LOGGING_, main.hFile)
                return True
            for attr in r['Event']['Attribute']:
                if attr['category'] == 'Payload installation':
                    if attr['value'] == filename:
                        LibIoC_DK.debugging("The hash value ALREADY stored as an attribute of : %s" %(r['Event']['info']), main._DEBUG_, main._LOGGING_, main.hFile)
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
        
        if type(val)==tuple and LibIoC_DK.isHash(val[2]):
            if not self.checkMISPHashEventExist(val[2]):
                if self.createMISPEventFromHash(val[2], filename):
                    return True
                else:
                    LibIoC_DK.debugging("Failed to create the MISP hash event", main._DEBUG_, main._LOGGING_, main.hFile)
                    return False
            else:
                eid = self.getMISPEventID(val[2])
                e = self.misp_connection.get_event(eid)
                self.misp_connection.add_named_attribute(e, category='Other', type_value='comment', value=LibIoC_DK.getFileName(filename))   # this will work as the ground truth of IoC
            return True
        elif type(val)==list:
            if self.createMISPEventFromReport(val, filename, _date):
                return True
            LibIoC_DK.debugging("Failed to create the MISP event: val(%s), filename(%s)" %(val, LibIoC_DK.getFileName(filename)), main._DEBUG_, main._LOGGING_, main.hFile)
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
            LibIoC_DK.debugging("[getMISPEventID] HTTPError occurred", main._DEBUG_, main._LOGGING_, main.hFile)
            return False 
            
        if not response.has_key('response'):
            return False
        for r in response['response']:
            if r['Event']['info'] == filename:
                return r['Event']['id']
            if LibIoC_DK.isHash(filename):
                for attr in r['Event']['Attribute']:
                    if attr['category'] == 'Payload installation':
                        if attr['value'] == filename:
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
        LibIoC_DK.debugging("Creating the MISP report event: %s" %(LibIoC_DK.getFileName(filename)), main._DEBUG_, main._LOGGING_, main.hFile)
        
        '''
        # if the MISP event for the filename already exists, add ioc in the event
        eid = self.getMISPEventID(LibIoC_DK.getFileName(filename))
        if eid:
            event = self.misp_connection.get_event(eid)
            for attr in ioc:
                self.addAttribute(event, attr)
            return False           
        '''
        if self.checkMISPReportEventExist(filename):
            LibIoC_DK.debugging("The MISP report event ALREADY exists", main._DEBUG_, main._LOGGING_, main.hFile)
            return False
        
        try:
            if _date is not None:
                #_date = datetime.datetime.strptime(_date, "%m/%d/%Y").strftime("%Y-%m-%d")
                _date = _date.split("/");
                if int(_date[0]) > 12:
                    _date = datetime.date(int(_date[0]),int(_date[1]),int(_date[2])).isoformat();
                else:
                    _date = datetime.date(int(_date[2]),int(_date[0]),int(_date[1])).isoformat();
        except Exception as e:
            print e
                        
        event = self.misp_connection.new_event(0, 1, 2, LibIoC_DK.getFileName(filename), date=_date)
        self.misp_connection.add_named_attribute(event, category='Other', type_value='comment', value=LibIoC_DK.getFileName(filename))   # this will work as the ground truth of IoC

        if main._STAT_ and self.ioc_stat.report_name != filename:
            self.ioc_stat.setReportBuffer(filename)
        
        if main._PARALLELIZE_ATTRIB_ADDITION_:
            # Parallelized Version
            print('[Report] Parallelized attribute storing...')
            attr_added = joblib.Parallel(joblib.cpu_count())(delayed(addAttribute)(self, event, attr, filename) for attr in ioc)   
        else:
            # Sequential Version
            attr_added = False
            for attr in ioc:
                attr_added = self.addAttribute(event, attr, filename) or attr_added
                
        if (type(attr_added) is bool and not attr_added):
            self.misp_connection.delete_event(event['Event']['id'])
            LibIoC_DK.debugging("NO attribute added for the report: %s" %(LibIoC_DK.getFileName(filename)), main._DEBUG_, main._LOGGING_, main.hFile)
            return False
        if type(attr_added) is list:
            if not(True in attr_added):
                self.misp_connection.delete_event(event['Event']['id'])
                LibIoC_DK.debugging("NO attribute added for the report: %s" %(LibIoC_DK.getFileName(filename)), main._DEBUG_, main._LOGGING_, main.hFile)
                return False
            
        LibIoC_DK.debugging("The MISP report event created", main._DEBUG_, main._LOGGING_, main.hFile)
        return True
    
        
    ################################################################
    # Create the MISP event from the analysis result malware hash.
    # @ input
    #    _hash: the malware hash value to be analyzed and created MISP event.
    #    filename: the root filename where the hash value is originated.
    # @ output
    #    Return True if the MISP event is created, otherwise return False.
    def createMISPEventFromHash(self, _hash, filename, additional_hash=False):
        LibIoC_DK.debugging("Creating the MISP hash event: %s" %(_hash), main._DEBUG_, main._LOGGING_, main.hFile)
            
        _hash = _hash.lower()
        # if the MISP event for the hash value already exists, stop the further process.
        if self.checkMISPHashEventExist(_hash):
            LibIoC_DK.debugging("The MISP hash event ALREADY exists", main._DEBUG_, main._LOGGING_, main.hFile)
            return False
                
        result = self.malware_repo_connector.getMalwareInfo(_hash)
        
        if not result:
            return False
                
        event = self.misp_connection.new_event(0, 1, 2, _hash)
        self.misp_connection.add_named_attribute(event, category='Other', type_value='comment', value=LibIoC_DK.getFileName(filename))   # this will work as the ground truth of IoCs      
        
        # the first three attributes in the result is md5, sha1, and sha256 representation malware hash, so manually store them in the event.
        md5=result.pop(0)[2]
        sha1=result.pop(0)[2]
        sha256=result.pop(0)[2]
        
        self.misp_connection.add_hashes(event, category='Payload installation', md5=md5)
        if main._STAT_:
            self.ioc_stat.addCategory2('hash')
        self.misp_connection.add_hashes(event, category='Payload installation', sha1=sha1)
        if main._STAT_:
            self.ioc_stat.addCategory2('hash')
        self.misp_connection.add_hashes(event, category='Payload installation', sha256=sha256)
        if main._STAT_:
            self.ioc_stat.addCategory2('hash')
        
        if main._DOWNLOAD_MALWARE_:
            sample_path = self.config['SampleRoot']+'/'+LibIoC_DK.getReportPublicationYear(filename)
            if not os.path.exists(sample_path+'/'+_hash):
                malware_buffer = self.malware_repo_connector.downloadMalware(sha256, False)
                if malware_buffer:
                    if not os.path.exists(sample_path):
                        os.makedirs(sample_path)
                    f = open(sample_path+'/'+_hash, 'wb')
                    f.write(malware_buffer)
                    f.close()
                    extracted = self.malware_repo_connector.unzipMalware(sample_path+'/'+_hash, sample_path)
                    if extracted.lower() != _hash.lower():
                        os.remove(sample_path+'/'+_hash)
                        _hash = extracted
                    
                header_info = LibIoC_DK.getMalwareHeaderInfo(sample_path+'/'+_hash)
                if header_info is not None:
                    self.addMalwareHeaderInfo(header_info, event)            
        
        if main._STAT_ and self.ioc_stat.report_name != filename:
            self.ioc_stat.setReportBuffer(filename)
           
        if main._PARALLELIZE_ATTRIB_ADDITION_:
            # Parallelized Version
            print('[Hash] Parallelized attribute storing...')
            joblib.Parallel(joblib.cpu_count())(delayed(addAttribute)(self, event, attr) for attr in result)   
        else:
            # Sequential Version
            for attr in result:
                self.addAttribute(event, attr, filename)

        LibIoC_DK.debugging("The MISP hash event created", main._DEBUG_, main._LOGGING_, main.hFile)
        return True
            
            
    def addMalwareHeaderInfo(self, info, event):
        if info is None:
            return 
        
        if 'TimeStamp' in info:
            event['Event']['date'] = info['TimeStamp'].partition(" ")[0]
            self.misp_connection.update(event)
            self.misp_connection.add_named_attribute(event, type_value='External analysis', category='text', value=info['TimeStamp'], comment='TimeStamp')  
        elif 'Author' in info:
            self.misp_connection.add_named_attribute(event, type_value='External analysis', category='text', value=info['Author'], comment='Author')  
        elif 'Title' in info:
            self.misp_connection.add_named_attribute(event, type_value='External analysis', category='text', value=info['Title'], comment='Title')  
        elif 'Packer' in info:
            self.misp_connection.add_named_attribute(event, type_value='External analysis', category='text', value=info['Packer'], comment='Packer')  
            
        return

    
    def addAttribute(self, event, attr, filepath):
        LibIoC_DK.debugging("Adding Attribute: filename(%s), attribute(%s)" %(LibIoC_DK.getFileName(filepath),attr) , main._DEBUG_, main._LOGGING_, main.hFile)
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
                LibIoC_DK.debugging("[checkAttribute] HTTPError while searching "+attr, main._DEBUG_, main._LOGGING_, main.hFile)
                return False 
            except:
                return False 
                
            if response.has_key('response'):
                retval = []
                for e in response['response']:
                    found = False
                    for i in range(len(e['Event']['Attribute'])):
                        if e['Event']['Attribute'][i]['value'] == attr.lower():
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
                        if i['value'] == attr.lower():
                            return True
        return False
    
    
    def exportXML_EID(self, from_idx, to_idx, output_filename):
        import xml.etree.ElementTree as ET
        root = ET.Element('CTIMinerDataset')
        for i in range(from_idx, to_idx):
            try:
                event = self.misp_connection.get_event(i)
            except:
                print('exportXML exception!')
                continue
            if 'message' in event and event['message'] == 'Invalid event.':
                continue
            
            root = self.addEventDataToElementTree(root, event)
            
        tree = ET.ElementTree(root)
        tree.write(output_filename)
        return
    
    # TODO:
    def exportXML_Date(self, year, event_type, output_filename):
        #import xml.etree.ElementTree as ET
        from lxml import etree as ET
        root = ET.Element('CTIMinerDataset')
        
        report_event = [];
        for mm in range(1,13):
            if mm < 10:
                from_date = str(year)+"-0%d-01" %(mm)
                to_date = str(year)+"-0%d-31" %(mm)
            else:
                from_date = str(year)+"-%d-01" %(mm)
                to_date = str(year)+"-%d-31" %(mm)
            try:
                ee = self.misp_connection.search(date_from=from_date, date_to=to_date)['response']
            except Exception as e:
                print('error %s / (year=%d, month=%d)' %(str(e), year, mm))
                continue
            
            for e in ee:
                if LibIoC_DK.isHash(e['Event']['info']):
                    continue
                else:
                    if event_type =='report':
                        root = self.addEventDataToElementTree(root, e)
                    elif event_type =='malware':
                        report_event.append(e)
                
        if event_type =='report':
            tree = ET.ElementTree(root)
            f = open(output_filename, 'wb')
            f.write(ET.tostring(tree, pretty_print=True))
            f.close()
            return
        
        for r in report_event:
            for yy in range(2008, 3000):
                for mm in range(1,13):
                    try:
                        if mm < 10:
                            from_date = str(yy)+"-0%d-01" %(mm)
                            to_date = str(yy)+"-0%d-31" %(mm)
                        else:
                            from_date = str(yy)+"-%d-01" %(mm)
                            to_date = str(yy)+"-%d-31" %(mm)  
                        ee = self.misp_connection.search(values=r['Event']['info'], category="Other", type_attribute="comment", date_from=from_date, date_to=to_date)['response']
                        for e in ee:
                            if LibIoC_DK.isHash(e['Event']['info']):
                                root = self.addEventDataToElementTree(root, e)
                    except Exception as e:
                        print('error %s / %s (month=%d, year=%d)' %(str(e), r['Event']['info'], mm, yy))
                        continue
                    
        tree = ET.ElementTree(root)
        f = open(output_filename, 'wb')
        f.write(ET.tostring(tree, pretty_print=True))
        f.close()
        return 
        
        
    def addEventDataToElementTree(self, tree_root, event):
        import dicttoxml
        import xml.etree.ElementTree as ET
        xml = ET.fromstring( dicttoxml.dicttoxml(event) )
        tmp = xml.find('Event')
        
        eventroot = ET.SubElement(tree_root, 'Event')
        
        ET.SubElement(eventroot, 'id').text = tmp.find('id').text
        ET.SubElement(eventroot, 'date').text = tmp.find('date').text
        ET.SubElement(eventroot, 'info').text = tmp.find('info').text
        
        for i in tmp.find('Attribute').findall('item'):
            item_root = ET.SubElement(eventroot, 'Attribute')

            ET.SubElement(item_root, 'category').text = i.find('category').text
            ET.SubElement(item_root, 'comment').text = i.find('comment').text
            ET.SubElement(item_root, 'value').text = i.find('value').text
            ET.SubElement(item_root, 'type').text = i.find('type').text
            ET.SubElement(item_root, 'id').text = i.find('id').text
            
        return tree_root
            
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
    attr_lower_case = attr[2].lower().replace('[.]', '.')
    
    attribute_added = False
    event_name, source_name = connector.getEventFileName(event = event)
    
    if not event_name:
        return False
    
    try:
        event_name = event_name.encode('utf-8')
        source_name = source_name.encode('utf-8')
    except:
        return False

    # if the attribute is already stored in the MISP event, skip it
    tmp_id = connector.checkAttribute(attr=attr[2])
    sharedIoC = False
    if tmp_id:
        for curr_id in tmp_id:
            if str(event['Event']['id']) == curr_id:
                return False
            else:
                if LibIoC_DK.isHash(event_name):
                    for a in event['Event']['Attribute']:
                        if a['category'] == 'Other' and a['value'] == connector.misp_connection.get_event(curr_id)['Event']['info']:
                            if main._STAT_:
                                connector.ioc_stat.addCategory3(attr_lower_case, connector.ioc_stat.convertIoCType(attribute_type))  # category 3
                            sharedIoC = True
                elif LibIoC_DK.isHash(connector.misp_connection.get_event(curr_id)['Event']['info']):
                    e = connector.misp_connection.get_event(curr_id)
                    for a in e['Event']['Attribute']:
                        if a['category'] == 'Other' and a['value'] == event['Event']['info']:
                            if main._STAT_:
                                connector.ioc_stat.addCategory3(attr_lower_case, connector.ioc_stat.convertIoCType(attribute_type))  # category 3
                            sharedIoC = True
                
                if sharedIoC:
                    break
            
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
        elif attribute_type == 'dest_ip':
            connector.misp_connection.add_ipdst(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'email':
            connector.misp_connection.add_email_src(event, attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'cve':
            connector.misp_connection.add_named_attribute(event, category=attribute_category, type_value='vulnerability', value=attr[2], comment=attribute_comment)
            attribute_added = True
#        elif attribute_type == 'registry':
#            connector.misp_connection.add_named_attribute(event, category=attribute_category, type_value='regkey', value=attr[2], comment=attribute_comment)
#            attribute_added = True
        elif attribute_type == 'filename':
            if LibIoC_DK.isFileofInterest(attr[2]):
                connector.misp_connection.add_named_attribute(event, category=attribute_category, type_value='filename', value=attr[2], comment=attribute_comment)
                attribute_added = True
#        elif attr[0] == 'Filepath':
#            connector.misp_connection.add_named_attribute(event, category='External analysis', type_value='text', value=attr[1], comment='file path')
#            attribute_added = True
        elif attribute_type == 'pdb':
            connector.misp_connection.add_named_attribute(event, category='Artifacts dropped', type_value='pdb', value=attr[2], comment=attribute_comment)
            attribute_added = True
        elif attribute_type == 'signcheck':
            connector.misp_connection.add_named_attribute(event, category=attribute_category, type_value='text', value=attr[2], comment=attribute_comment)        
            attribute_added = True
                
        # If a malware hash is found, check if it is already stored in MISP as an attribute.
        # If MISP has already stored it, just add it as an attribute of the current event. 
        # Otherwise, create new MISP event if the analysis result could be found from malware repository.
        # If no the analysis result found from the repository, just add it as an attribute of the current event.
        elif attribute_type == 'md5' or attribute_type == 'sha1' or attribute_type == 'sha256':
            if connector.checkAttribute(attr_lower_case):
                if attribute_type == 'md5':
                    connector.misp_connection.add_hashes(event, category=attribute_category, md5=attr_lower_case, comment=attribute_comment)
                elif attribute_type == 'sha1':
                    connector.misp_connection.add_hashes(event, category=attribute_category, sha1=attr_lower_case, comment=attribute_comment)
                elif attribute_type == 'sha256':
                    connector.misp_connection.add_hashes(event, attribute_category, sha256=attr_lower_case, comment=attribute_comment)
                attribute_added = True                
            elif LibIoC_DK.isHash(event['Event']['info']) and connector.createMISPEventFromHash(attr_lower_case, filepath) and main._STAT_:
                connector.ioc_stat.increaseAnalyzedAdditionalHash()

        elif attribute_type == 'string':
            connector.misp_connection.add_named_attribute(event, category=attribute_category, type_value='text', value=attr[2], comment=attribute_comment)        
            attribute_added = True
            
    # IoC statistics calculation.
    if main._STAT_:
        if not sharedIoC:# and attribute_added:
            if LibIoC_DK.isHash(event_name):
                if attribute_added:
                    if connector.ioc_stat.checkIoCInReport(attr[2]) or connector.ioc_stat.checkIoCInReport(attr_lower_case):
                        connector.ioc_stat.addCategory2(connector.ioc_stat.convertIoCType(attribute_type)) # category 2
                    else:       
                        connector.ioc_stat.addCategory4(connector.ioc_stat.convertIoCType(attribute_type))  # category 4
            else:
                if attribute_added:
                    connector.ioc_stat.addCategory1(connector.ioc_stat.convertIoCType(attribute_type)) # category 1
                else:
                    connector.ioc_stat.addcategory5(connector.ioc_stat.convertIoCType(attribute_type)) # category 5
            
    return attribute_added



# This main module generates CTI dataset from MISP database.
# The final dataset only contains the necessary information to be the dataset excluding needless data such as organization info, uuid, Related Event.
# The data included in the final dataset is defined in 'exportXML' function in MISPConenctor class. 
if __name__ == '__main__':
    
    # Load configuration file
    config_value = main.getConfig(main.config_file)
    file_names = main.getFileName(config_value['ReportRoot'])
    import IoCStatistics
    ioc_stat = IoCStatistics.IoCStatistics()
    misp = MISPConnector(config_value, ioc_stat)
    '''
    junk_size = 3000
    from_idx = 1
    to_idx = 10006
    num_junk = int(math.ceil(float(to_idx-from_idx+1)/junk_size))
    for i in range(num_junk):
        junk_from = (i)*junk_size+1
        junk_to = (i+1)*junk_size
        if junk_to > to_idx:
            junk_to = to_idx
        filename = 'CTIDataset('+str(junk_from)+'-'+str(junk_to)+').xml'
        print 'Generating file...: '+filename
        misp.exportXML_EID(junk_from, junk_to, filename)
        print ' Done!'
    '''
    
    for yy in range(2018, 2020):
        misp.exportXML_Date(yy, 'report', 'CTIDataset_'+str(yy)+'_ReportEvent.xml')
        misp.exportXML_Date(yy, 'malware', 'CTIDataset_'+str(yy)+'_MalwareEvent.xml')
        
