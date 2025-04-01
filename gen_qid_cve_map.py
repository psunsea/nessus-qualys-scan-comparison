#!/usr/bin/python3
import json
import sys
import gzip
import xml.etree.ElementTree as ET 

def main():
    gzxmlfile = None
    if len(sys.argv) == 2:
        gzxmlfile = sys.argv[1]
    else:
        print("Usage: gen_qid_cve_map.py [path to qualys-knowledgeBase-########.xml.gz] > qid_cve_map.json")
        exit(1)

    tree = ET.parse(gzip.open(gzxmlfile))

# <?xml version="1.0" encoding="UTF-8" ?>
# <!DOCTYPE KNOWLEDGE_BASE_VULN_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd">
# <KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
#   <RESPONSE>
#     <DATETIME>2025-03-05T04:08:42Z</DATETIME>
# <VULN_LIST>
#   <VULN>
#     <QID>6</QID>
#     <VULN_TYPE>Information Gathered</VULN_TYPE>
#     <SEVERITY_LEVEL>1</SEVERITY_LEVEL>
#     <TITLE><![CDATA[DNS Host Name]]></TITLE>
#     <CATEGORY>Information gathering</CATEGORY>
#     <LAST_SERVICE_MODIFICATION_DATETIME>2018-01-04T17:39:37Z</LAST_SERVICE_MODIFICATION_DATETIME>
#     <PUBLISHED_DATETIME>1999-01-01T08:00:00Z</PUBLISHED_DATETIME>
#     <PATCHABLE>0</PATCHABLE>
#     <SOFTWARE_LIST>
#       <SOFTWARE>
#         <PRODUCT><![CDATA[dns_server]]></PRODUCT>
#         <VENDOR><![CDATA[none]]></VENDOR>
#       </SOFTWARE>
#     </SOFTWARE_LIST>
    # <CVE_LIST>
    #   <CVE>
    #     <ID><![CDATA[CVE-2006-3059]]></ID>
    #     <URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3059]]></URL>
    #   </CVE>
    # </CVE_LIST>
#     <DIAGNOSIS><![CDATA[The fully qualified domain name of this host, if it was obtained from a DNS server, is displayed in the RESULT section.]]></DIAGNOSIS>
#     <PCI_FLAG>0</PCI_FLAG>
#     <DISCOVERY>
#       <REMOTE>1</REMOTE>
#     </DISCOVERY>
#   </VULN>
    # get root element (this can take a long time)
    result_root = tree.getroot() 
    vuln_list = result_root.findall('RESPONSE/VULN_LIST')
    vulns = vuln_list[0].findall('VULN')
    
    output = []
    for vuln in vulns:
        qid = vuln.find('QID').text
        vuln_type = vuln.find('VULN_TYPE').text
        cve_list = vuln.findall('CVE_LIST')
        cve_nodes = cve_list[0].findall('CVE') if len(cve_list) == 1 else []
        cve_arr = []
        for cve_node in cve_nodes:
            cve_arr.append(cve_node.find('ID').text); 
        cves = ','.join(cve_arr)

        extracted_vuln = {
            'qid': qid,
            'vuln_type': vuln_type,
            'cve': cves
        }
        output.append(extracted_vuln)

    print(json.dumps(output, indent=4))

if __name__ == '__main__':
    main()
