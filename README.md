# FRC-CAN-Wireshark
Wireshark plugin for dissecting and interpreting CAN packets as used in the FIRST Robotics Competition control system

## Capture
So far, this code has been tested using a Microchip CAN Bus Analyzer: https://www.microchip.com/developmenttools/ProductDetails/apgdt002 with rkollataj's Linux kernel drivers: https://github.com/rkollataj/mcba_usb . This creates 'can0' as a network interface, from which Wireshark can capture. 

However, any other CAN hardware interface compatible with socketCAN (https://elinux.org/CAN_Bus) should work. 

I'm also planning a Raspberry Pi hat with a CAN controller. The Pi, with CAN kernel drivers, should be usable as a remote capture interface for Wireshark.

## Protocols
To the best of my knowledge, none of the major FRC CAN device manufacturers (NI, CTRE, Rev) publish documentation for the bitfields in their CAN frames. Therefore, these dissectors are based on reverse-engineering actual CAN traffic, and finding stray bits of code on the Internet. Use at your own risk. 
