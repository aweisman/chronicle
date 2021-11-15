#!/usr/bin/python3           # This is server.py file

from os import read
import socket               # Import socket module
import json                 # Import JSON module
from threading import Thread 
from _thread import *
import requests

# Multithreaded Python server : TCP Server Socket Thread Pool
class ClientThread(Thread): 
 
    def __init__(self,ip,port): 
        Thread.__init__(self) 
        self.ip = ip 
        self.port = port 
        print ("[+] New server socket thread started for " + ip + ":" + str(port))
 
    def run(self): 
        while True : 
            recdata = c.recv(51200) 
            if not recdata: break
            print('Data payload: ', len(recdata), '\n')

            # jsonAlert = json.loads(data)  # Read JSON alert
            # print ('JSON Received by JSON module:\n', jsonAlert)
            
            # print(recdata)

            lines = recdata.split(b'\n')    # Array of alerts sent in a single connection; json.loads can only process one JSON alert object at a time.
            for line in lines:
                if not line: break
                # print('line of data: \n', line)
                jsonAlert = json.loads(line)
                # print(jsonAlert)

                ts = jsonAlert['timestamp'][0:-2]+':'+jsonAlert['timestamp'][-2:]   # Assign timestamp from JSON Alert to ts
                # print ('Timestamp extracted: ', ts)

                event_uuid = jsonAlert['bricata']['event_uuid']
                event_type = jsonAlert['event_type']
                try:
                    event_source = jsonAlert['bricata']['event_source']
                    # print('event_source: ', event_source)
                except:
                    event_source = None
                    print('Skipped event_source\n')

                signature = jsonAlert['alert']['signature']
                pivot = "https://"+cmcIP+"/#/views/alerts?filter={%22operator%22:%22And%22,%22nodes%22:[{%22variable%22:%22event_uuid%22,%22value%22:%22"+event_uuid+"%22}]}"
                # print (pivot)

                # metadata = {'event_timestamp': ts, 'event_type': cEventType, "product_name": cProductName, "vendor_name": cVendorName, 'product_log_id': event_uuid, 'product_event_type': event_source, 'description': signature}  # Create dictionary for Chronicle metadata
                metadata = {'event_timestamp': ts, 'event_type': cEventType, "product_name": cProductName, "vendor_name": cVendorName, 'product_log_id': event_uuid, 'product_event_type': event_source, 'url_back_to_product': pivot, 'description': signature}  # Create dictionary for Chronicle metadata
                # metadataJsonString = '"metadata": ' + json.dumps(metadata, indent=4)
                # print ('metadata JSON String:\n', metadataJsonString, '\n')
                
                srcIP = jsonAlert['src_ip']
                srcPort = jsonAlert['src_port']
                destIP = jsonAlert['dest_ip']
                destPort = jsonAlert['dest_port']
                
                principal = {'ip':srcIP, 'port': srcPort}
                # principleJsonString = '"principle": ' + json.dumps(principle, indent=4)
                # print ('principle JSON String:\n', principleJsonString)
                
                target = {'ip': destIP, 'port': destPort}

                sensorIPv4 = jsonAlert['bricata']['sensor_ipv4']
                sensorHostname = jsonAlert['bricata']['sensor_hostname']
                observer = {'hostname': sensorHostname, 'ip': [sensorIPv4]}

                jsonBlob = {'events': [{'metadata': metadata, 'principal': principal, 'target': target, 'observer': observer}]}
                # jsonBlob = {'events': [{'metadata': metadata, 'principal': principal}]}
                print ('JSON Blob:\n', jsonBlob)
                print(json.dumps(jsonBlob, indent=4))

                r = requests.post(url = cURL, data = json.dumps(jsonBlob))
                print(r.request.url)
                print(r.request.headers)
                print(r.request.body)
                print('Chronicle response: ', r.text)

            # c.send('Thank you for connecting'.encode())
        c.close()                # Close the connection


cmcIP = '172.16.10.40'
with open("chron.txt") as f:    # Read key from local file
    cKey = f.read()
cURL = 'https://malachiteingestion-pa.googleapis.com/v1/udmevents?key='+cKey
cEventType = 'EVENTTYPE_UNSPECIFIED'
# cEventType = 0
cProductName = 'Bricata'
cVendorName = 'Bricata'


s = socket.socket()         # Create a socket object
host = socket.gethostbyname('localhost') # Get local machine name
print ('Host: ', host)
port = 12345                # Reserve a port for your service.
s.bind(('', port))        # Bind to the port

threads = [] 

s.listen(5)                 # Now wait for client connection.    print "Multithreaded Python server : Waiting for connections from TCP clients..." 

while True: 
    (c, (ip,port)) = s.accept() 
    print ('\n******************\nGot connection from', ip, port, '\n')
    newthread = ClientThread(ip,port) 
    newthread.start() 
    threads.append(newthread)
 
# for t in threads: 
#     t.join() 