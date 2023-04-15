package de.al1c3.teensytool;
import jssc.SerialPort;
import jssc.SerialPortException;

public class TeensyReboot {
    public static void rebootTeensySerial(String portNum) throws SerialPortException {
        SerialPort port = new SerialPort(portNum);
        port.openPort();
        port.setParams(134, 0, 0, 0, false, false);
        port.closePort();
    }
}
