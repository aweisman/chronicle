#!/usr/bin/python3           # This is server.py file

# Bricata Chronicle Forwarder
# Version: 0.1
# Written by: Andrew Weisman
# Last modified: 

'''
This script was written as a prototype forwarder for sending export data from
Bricata to Google Chronicle SIEM. The data from the Bricata JSON event is
normalized into the Chronicle UDM JSON format.
There are many event types enumerated by Chronicle, but for the initial code
only the GENERIC_EVENT type is used. Metadata export should be broken down into
specific NETWORK_?? event types that Chronicle supports based on app/protocol,
e.g. DNS, HTTP, FTP. For those metadata types that are outside of the small set
supported by Chronicle, there is a NETWORK_UNCATEGORIZED type.
'''
from os import read         # Import read module to read key file
import socket               # Import socket module
import json                 # Import JSON module
from threading import Thread 
from _thread import *
import requests
import logging
import time

cmcIP = '172.16.10.40'
with open("chron.txt") as f:    # Read key from local file
    cKey = f.read()
cURL = 'https://malachiteingestion-pa.googleapis.com/v1/udmevents?key='+cKey
cEventType = 'GENERIC_EVENT'
cProductName = 'Bricata'
cVendorName = 'Bricata'

logging.basicConfig(filename="threaded_listener.log")

### Multithreaded Python server : TCP Server Socket Thread Pool
class ClientThread(Thread): 
 
    def __init__(self,ip,port): 
        Thread.__init__(self) 
        self.ip = ip 
        self.port = port 
        print ("[+] New server socket thread started for " + ip + ":" + str(port))
 
    def run(self): 
        totalData = []      # Store received data in list until socket is closed
        data = []           # Store the data received as a string
        aggJSONblob = []    # Store the complete JSON blob of all records received
        startTime = time.time()     # Used only for DEBUG

        while True :         # Accumulate data from socket receive buffer
            recdata = c.recv(4096)
            if not recdata:         # Break when socket is closed by sender
                print('###### recdata null ######\n')
                break
            totalData.append(recdata.decode())
            data = ''.join(totalData)

        print('=======> Receive data loop: ', time.time() - startTime, '\n')
        print('Data payload: ', len(data), '\n')

        lines = data.split('\n')    # Array of alerts sent in a single connection; json.loads can only process one JSON alert object at a time.
        # lines = data.split(b'\n')    # Array of alerts sent in a single connection; json.loads can only process one JSON alert object at a time.
        print('Elements in lines array: ', len(lines), '\n')
        lineCnt = 0             # Use for DEBUG purposes
        for line in lines:      # Process each JSON alert object
            if not line:
                print('[-] Break line of data: \n', line)
                break
            lineCnt += 1        # Use for DEBUG purposes
            print('Line number: ', lineCnt, ' -- Line length: ', len(line), '\n')
            try:
                jsonAlert = json.loads(line)
            except:
                logging.error("json.loads exception:\n" + line.decode())
                print('\n@@@@@@@@ json.loads exception for following record:\n', line)
                break
            # print(jsonAlert)

            '''
            Gather Chronicle UDM 'metadata' stanza data from the Bricat JSON.
            '''
            ts = jsonAlert['timestamp'][0:-2]+':'+jsonAlert['timestamp'][-2:]   # Assign timestamp from JSON Alert to ts
            # print ('Timestamp extracted: ', ts)

            event_uuid = jsonAlert['bricata']['event_uuid']
            # event_type = jsonAlert['event_type']
            try:
                event_source = jsonAlert['bricata']['event_source']
                # print('event_source: ', event_source)
            except:
                event_source = None
                print('Skipped event_source\n')

            signature = jsonAlert['alert']['signature']
            # Create 'pivot' URL to be included in the metadata stanza
            pivot = "https://"+cmcIP+"/#/views/alerts?filter={%22operator%22:%22And%22,%22nodes%22:[{%22variable%22:%22event_uuid%22,%22value%22:%22"+event_uuid+"%22}]}"
            # print (pivot)

            metadata = {'event_timestamp': ts, 'event_type': cEventType, "product_name": cProductName, "vendor_name": cVendorName, 'product_log_id': event_uuid, 'product_event_type': event_source, 'url_back_to_product': pivot, 'description': signature}  # Create 'metadata' stanza for Chronicle metadata
            # metadataJsonString = '"metadata": ' + json.dumps(metadata, indent=4)
            # print ('metadata JSON String:\n', metadataJsonString, '\n')
            
            '''
            Gather Chronicle UDM  'principal' and 'target' stanzas data from the
            Bricata JSON.
            '''
            srcIP = jsonAlert['src_ip']
            srcPort = jsonAlert['src_port']
            destIP = jsonAlert['dest_ip']
            destPort = jsonAlert['dest_port']
            
            principal = {'ip':srcIP, 'port': srcPort}   # Build 'principal' stanza
            # principleJsonString = '"principle": ' + json.dumps(principle, indent=4)
            # print ('principle JSON String:\n', principleJsonString)
            
            target = {'ip': destIP, 'port': destPort}

            '''
            Gather Chronicle UDM  'observer' stanza data from the Bricata JSON.
            '''
            sensorIPv4 = jsonAlert['bricata']['sensor_ipv4']
            sensorHostname = jsonAlert['bricata']['sensor_hostname']
            observer = {'hostname': sensorHostname, 'ip': [sensorIPv4]} # Build 'observer' stanza

            '''
            Code commented below was the first method of building the JSON object
            to submit to Chronicle. It is preferred to group multiple records, up
            to 1MB in a single API submission.
            '''
            ### Original JSON record to be submitted as individual object
            # jsonBlob = {'events': [{'metadata': metadata, 'principal': principal, 'target': target, 'observer': observer}]}
            # print ('JSON Blob:\n', jsonBlob)
            # print(json.dumps(jsonBlob, indent=4))

            # r = requests.post(url = cURL, data = json.dumps(jsonBlob))
            # print(r.request.url)
            # print(r.request.headers)
            # print(r.request.body)
            # print('Chronicle response: ', r.text)

            '''
            Build individual Chronicle JSON records for each alert/metadata record in an 
            export flow received from the Bricata Sensor/CMC. Collect the records
            in a list to use later to assemble all records contained in the
            flow into a single JSON object to be submitted.
            '''
            aJSONblob = {'metadata': metadata, 'principal': principal, 'target': target, 'observer': observer}
            aggJSONblob.append(json.dumps(aJSONblob))
            
        # c.send('Thank you for connecting'.encode())   # Test response
        '''
        Assmeble all records in list into a single string with the leading 
        brace, "events" object key, bracket, decoded JSON and a final bracket
        and brace.
        '''
        finalJSONblob = '{"events": [' + ', '.join(aggJSONblob) + ']}'
        print('\n^^^^^^^^ Aggregated JSON Blob with length of : ',len(finalJSONblob), '\n', finalJSONblob, '\n\n')
        r = requests.post(url = cURL, data = finalJSONblob)     # Submit to Chronicle API
        print(r.request.url)
        print(r.request.headers)
        print(r.request.body)
        print('Chronicle response: ', r.text)
        c.close()                # Close the connection


s = socket.socket()         # Create a socket object
host = socket.gethostbyname('localhost') # Get local machine name
print ('Host: ', host)
port = 12345                # Reserve a port for your service.
s.bind(('', port))        # Bind to the port

threads = [] 
# s.settimeout(None)
s.listen(5)                 # Now wait for client connection.    print "Multithreaded Python server : Waiting for connections from TCP clients..." 

while True: 
    (c, (ip,port)) = s.accept() 
    print ('\n******************\nGot connection from', ip, port, '\n')
    newthread = ClientThread(ip,port) 
    newthread.start() 
    threads.append(newthread)
 
# for t in threads: 
#     t.join() 