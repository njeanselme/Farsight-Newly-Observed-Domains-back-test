# Farsight-Newly-Observed-Domains-back-test
To demonstrate the value of Farsight Newly Observed Domains, a good way is to back test all your Farsight NOD hits and check domains and IPs against TIDE 7 days after.

It is what this code does, simply provide a csv file with Query column (can be csp.infoblox.com security-activity_security-events.csv file), then the code will:
- download TIDE domains and IPs
- deduplicate NOD domains and add IPs to the list of IOCs
- extract l2 domains and add IPs to the list of IOCs
- resolve all domains and add IPs to the list of IOCs
- test the list of IOCs against TIDE IPs and domains
- generate a report

example output:
2020-07-01 10:22:14,428 - root - INFO - IOCs in Farsight Newly Observed Domains matches and in TIDE: 25
2020-07-01 10:22:14,428 - root - INFO - -- Description --                                   -- host --                                          -- ip --                                          
2020-07-01 10:22:14,429 - root - INFO - UncategorizedThreat_Generic                         whitepolicy12.live                                                                                    
2020-07-01 10:22:14,429 - root - INFO - UncategorizedThreat_Generic                         whitepolicy7.live                                                                                     
2020-07-01 10:22:14,429 - root - INFO - MalwareC2_Generic                                   froprooke.eu                                        217.78.245.4                                      
2020-07-01 10:22:14,430 - root - INFO - MalwareC2_Spyware                                   floridacovidaction.com                              192.0.78.25                                       
2020-07-01 10:22:14,430 - root - INFO - UncategorizedThreat_Generic                         winsecurity4.fr                                     ['149.202.151.198']                               
2020-07-01 10:22:14,430 - root - INFO - UncategorizedThreat_Generic                         hanginthere7.live                                                                                     
2020-07-01 10:22:14,430 - root - INFO - MalwareC2_Spyware                                   prebid-domain.com                                   81.17.18.197                                      
2020-07-01 10:22:14,431 - root - INFO - Policy_LookalikeDomains                             darknetflix.io                                      ['143.204.222.45', '143.204.222.23', '143.204.222.73', '143.204.222.71']   
2020-07-01 10:22:14,431 - root - INFO - MalwareC2_Generic                                   slash.mg                                            164.132.235.17                                    
2020-07-01 10:22:14,431 - root - INFO - MalwareC2_Mobile                                    pixna.fr                                            213.186.33.5                                      
2020-07-01 10:22:14,432 - root - INFO - UncategorizedThreat_Generic                         whitepolicy5.live                                                                                     
2020-07-01 10:22:14,432 - root - INFO - MalwareC2_Generic                                   kiliame.com                                         23.227.38.65                                      
2020-07-01 10:22:14,433 - root - INFO - UncategorizedThreat_Generic                         unterscheiden2.live                                                                                   
2020-07-01 10:22:14,434 - root - INFO - UncategorizedThreat_Generic                         wrtfkapcczx10.live                                                                                    
2020-07-01 10:22:14,435 - root - INFO - UncategorizedThreat_Generic                         exmatrikulato7.live                                                                                   
2020-07-01 10:22:14,435 - root - INFO - Phishing_Generic                                    infzonesrs.com                                                                                        
2020-07-01 10:22:14,436 - root - INFO - MalwareC2_Generic                                   merbouhanchallah.duckdns.org                        192.169.69.25                                     
2020-07-01 10:22:14,436 - root - INFO - UncategorizedThreat_Generic                         testnewips3.live                                                                                      
2020-07-01 10:22:14,437 - root - INFO - UncategorizedThreat_Generic                         wrtfkapcczx6.live                                                                                     
2020-07-01 10:22:14,437 - root - INFO - MalwareC2_Generic                                   healingdelhi.in                                     88.198.69.186                                     
2020-07-01 10:22:14,437 - root - INFO - MalwareC2_Generic                                   sumome.net                                          8.208.101.87                                      
2020-07-01 10:22:14,438 - root - INFO - LimitedDistro_MalwareGeneric                        barengannih.com                                                                                       
2020-07-01 10:22:14,438 - root - INFO - MalwareC2_Generic                                   floridacovidaction.com                              192.0.78.24                                       
2020-07-01 10:22:14,438 - root - INFO - UncategorizedThreat_Generic                         unterscheiden10.live                                                                                  
