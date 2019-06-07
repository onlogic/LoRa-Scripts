##LoRa OCCAM API README

#What is it?

The LoRa OCCAM API provides a set of tools to help you customize and develop your LoRa mPCIe Smart Gateway card. It will show how to navigate the communication protocols using Python to send and receive data packages from the module to the LoRa mPCIe card. 

The goal of this package is to provide all the tools needed for you to set up and customize your LoRa mPCIe Smart Gateway card for your own application. 

#Initial Set-up

You will need to install Python 3 prior to following this guide.

For reference, it will be helpful to follow the OCCAMSMART command reference guide for a complete list of SEND and RECEIVE commands. 

Please refer to Logic Supply’s LoRa mPCIe Smart Gateway card manual for information on how to install the LoRaWAN Network Stack and setup your LoRa device. 

After making all the necessary downloads, launch the Python shell.

#Applications

The LoRa OCCAM API follows the LoRa communication protocol to send and receive data packets between the card and module. These include, but are not limited to:

SEND Command Data Packets
* Transmit Frequency
* Transmit Start Time
* Modulation Bandwidth
* Data Rate
* Coding Rate


RECEIVE Command Data Packets
* Channel Frequency
* Status
* Time Stamp
* Data Rate
* Modulation
* Bandwidth
* Data Rate
* Coderate

These data packets can be modified based on application and sent to the LoRa card. 

#Support Limitations
Currently there is no support for the Windows OS on the OCCAM front end. Initial installation instructions such as web interface and device setup can only be done using the Linux operating system.

The data packets and commands list can be worked with in both the Linux and Windows operating systems using a serial interactive program such as, but not limited to, Python, C, and Javascript.
#Additional Resources
For additional information about LoRa mPCIe Smart Gateway card, please visit the official OCCAMSMART LoRa page.


For any further questions or concerns, please visit Onlogic’s US or EU technical support site. 


