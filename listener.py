#!/usr/bin/python3           # This is server.py file

import socket               # Import socket module
import json                 # Import JSON module

cmcIP = '172.16.10.40'

s = socket.socket()         # Create a socket object
host = socket.gethostbyname('localhost') # Get local machine name
print ('Host: ', host)
port = 12345                # Reserve a port for your service.
s.bind(('', port))        # Bind to the port

s.listen(5)                 # Now wait for client connection.
while True:
   c, addr = s.accept()     # Establish connection with client.
   print ('\n******************\nGot connection from', addr, '\n')
   data = c.recv(4096)
   # print ('JSON Received:\n %s', data)
   print('Data payload: ', len(data), '\n')

   jsonAlert = json.loads(data)  # Read JSON alert
   # print ('JSON Received by JSON module:\n', jsonAlert)
   
   ts = jsonAlert['timestamp']   # Assign timestamp from JSON Alert to ts
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

   metadata = {'event_timstamp':ts, 'event_type':'EVENTTYPE_UNSPECIFIED', "product_name":"Bricata", "vendor_name": "Bricata", 'product_log_id': event_uuid, 'product_event_type': event_source, 'url_back_to_product': pivot, 'description': signature}  # Create dictionary for Chronicle metadata
   metadataJsonString = '"metadata": ' + json.dumps(metadata, indent=4)
   print ('metadata JSON String:\n', metadataJsonString, '\n')
   
   srcIP = jsonAlert['src_ip']
   srcPort = jsonAlert['src_port']
   destIP = jsonAlert['dest_ip']
   destPort = jsonAlert['dest_port']
   
   principle = {'ip':[srcIP]}
   principleJsonString = '"principle": ' + json.dumps(principle, indent=4)
   print ('principle JSON String:\n', principleJsonString)
   
   jsonBlob = {'events': [{'metadata': metadata, 'principle': principle}]}
   print ('JSON Blob:\n', jsonBlob)
   print(json.dumps(jsonBlob, indent=4))

   c.send('Thank you for connecting'.encode())
   c.close()                # Close the connection

