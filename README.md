# Welcome to TeensyTool

This tool is **unfofficial** and **not** affiliated with the Teensy project or Paul Stoffregen. Also, it does not depend on any data protected under NDAs.


# Prerequisites
- Locked "Lockable Teensy 4.1"
- OpenJDK 11+
- The key.pem as generated by Teensy security tool
- An internet connection to download the files from teensyduino project (Tested with 1.57.2 and 1.59 beta 2)
- A *linear* (even non-continuous) ino.hex file as generated by teensyduino

# Build
mvn clean package

# Usage
## Reboot into Bootloader from running program
- Run java -jar < filename.jar > < Serial port >
- Teensy 4.1 will enter NXP Bootloader mode

## Generate ehex file for flashing with Teensy.exe
- Run java -jar < filename.jar > < key.pem > < Sketch.ino.hex > < Sketch.ino.ehex >
- Ehex file will be written

## Generate in memory and upload
- Go to NXP Bootloader, either by pressing the "program" button or by issuing the bootloader reboot via serial port
- Run java -jar < filename.jar > < key.pem > < Sketch.ino.hex >
- Ehex file will be generated in memory and then uploaded to Teensy 4.1

# Known Issues
- Padding is not implemented. This is probably just slowing down the upload, but should be fixed nonetheless.
- Missing Error handling
- Missing unit tests