# ModbusFunctioninNetwork

Modbus protocol is used a lot in industrial processes. There is a modbus function code field in the Modbus protocol. Thanks to this field, it is understood that the signals perform read and write operations. In fact, it is understood that more than one signal is read and written. 

In the tool I developed, if the modbus protocol is communicated in the network, it captures the value in the modbus function code field. Thanks to this field, we can see which modbus function code is in the network. If you see a different modbus function code in your network, it helps us to understand that there is a problem here, maybe an attack. 
