# nessus-qualys-scan-comparison
Compare the two Enterprise vulnerability scaning tools, Tenable Nessus Professional (Nessus) and Qualys Headless (QHS) scan resutls to evaluate their scan coverage.


# Preparations

## Qualys
QHS does not have CVE information in its scan results. It provides its enterprise customers with a regularly updated Qualys Knowledgebase file with the detailed information for all the QID's. In it, for each QID, it listed the CVE's associated. 

`gen_qid_cve_map.py` is a small tool to creaet a json map from the Qualys Knowledgebase file. It's for looking up qid -> cve, and can be loaded to memory with small footprint. 
