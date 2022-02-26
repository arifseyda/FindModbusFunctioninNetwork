# Find Modbus Function in Network

This asset management tool was developed in the National Testbed Center project (Center SAU - https://center.sakarya.edu.tr). The developed software has been tested in this test bed center.

Python pyshark library, which uses tshark infrastructure, is used to listen to the network.

Modbus protocol is widely used in industrial processes. There is a modbus function code field in the Modbus protocol. Thanks to this area, it is understood that the signals do read and write operations. In fact, read-write operations are performed in multiple signal.

In the tool I developed, if the modbus protocol is communicated in the network, it captures the value in the modbus function code field. Thanks to this field, we can see which modbus function code is in the network. If you see a different modbus function code in your network, it helps us to understand that there is a problem here, maybe an attack. 
