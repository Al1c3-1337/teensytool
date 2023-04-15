package de.al1c3.teensytool;

import org.bouncycastle.util.encoders.Hex;
import org.hid4java.*;
import org.hid4java.event.HidServicesEvent;

import java.io.IOException;

@SuppressWarnings({"unused", "SameParameterValue"})
public class NXPSDP implements HidServicesListener {
    private final HidDevice device;
    private final HidServices hidServices;

    /**
     * Create a new NXPSDP instance.
     * This tries to connect to the NXP Serial Data Programmer
     *
     * @throws IOException If no NXP SDP device is found
     */
    public NXPSDP() throws IOException {
        HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
        hidServicesSpecification.setAutoStart(false);
        hidServicesSpecification.setScanMode(ScanMode.SCAN_AT_FIXED_INTERVAL_WITH_PAUSE_AFTER_WRITE);
        hidServices = HidManager.getHidServices(hidServicesSpecification);
        hidServices.start();

        for (HidDevice hidDevice : hidServices.getAttachedHidDevices())
            if (hidDevice.getVendorId() == 0x1fc9 && hidDevice.getProductId() == 0x0135) {
                device = hidDevice;
                device.open();
                return;
            }
        throw new IOException("NXP SDP not found!");
    }

    /**
     * Close USB connection to NXP programmer.
     * This should be done after completing work with this class.
     */
    public void shutdown() {
        hidServices.shutdown();
    }

    /**
     * Send the Teensy secured loader
     *
     * @param loader The loader
     * @param address Loading address
     * @throws IOException If anything goes wrong
     */
    public void sendLoader(byte[] loader, int address) throws IOException {
        sdp_write_reg(address, 0);
        sdp_write_file(address, loader.length, (byte) 0x00);
        sdp_data(loader);
        sdp_jump(address);
    }

    /**
     * Execute code at specified address
     *
     * @param address Execution address
     * @throws IOException If anything goes wrong
     */
    public void jump(int address) throws IOException {
        sdp_jump(address);
    }

    /**
     * Reads a register specified by the supplied address
     * TODO: Complete and test this function
     *
     * @param addr register address
     * @param cnt number of bytes to read
     * @throws IOException If anything goes wrong
     */
    private void sdp_read_reg(int addr, int cnt) throws IOException {
        /*
         * SDP READ REGISTER
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0101       - SDP_READ_REG
         * 0xXXXXXXXX   - address
         * 0x20         - format
         * 0xXXXXXXXX   - count
         * 0x00000000   - value
         * 0x00         - reserved
         */
        byte[] command = Hex.decode("01010000000020000000000000000000");
        Utils.insertIntBE(command,2,addr);
        Utils.insertIntBE(command,7,cnt);
        if (device.sendFeatureReport(command, (byte) 0x01) == -1) {
            throw new IOException("SDP READ REG failed");
        }
        readToOut(false);
    }

    /**
     * Write data to specified register address
     *
     * @param addr Register address
     * @param val Value to write
     * @throws IOException If anything goes wrong
     */
    private void sdp_write_reg(int addr, int val) throws IOException {
        /*
         * SDP WRITE REGISTER
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0202       - SDP_WRITE_REG
         * 0xXXXXXXXX   - address
         * 0x20         - format
         * 0x00000004   - count
         * 0xXXXXXXXX   - value
         * 0x00         - reserved
         */
        byte[] command = Hex.decode("02020000000020000000040000000000");
        Utils.insertIntBE(command,2,addr);
        Utils.insertIntBE(command,11,val);
        if (device.write(command,command.length, (byte) 0x01) == -1)
            throw new IOException("SDP WRITE REG failed");
        readToOut(true);
    }

    /**
     * Get Status
     * TODO: Complete and test this function
     *
     * @throws IOException If anything goes wrong
     */
    private void sdp_status() throws IOException {
        /*
         * SDP GET STATUS
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0505       - SDP_ERROR_STATUS
         * 0x00000000   - address
         * 0x00         - format
         * 0x00000000   - count
         * 0x00000000   - value
         * 0x00         - reserved
         */
        byte[] command = Hex.decode("05050000000000000000000000000000");
        if (device.write(command,command.length, (byte) 0x01) == -1)
            throw new IOException("SDP STATUS failed");
        readToOut(false);
    }

    /**
     * Write DCD
     * TODO: Complete and test this function
     *
     * @param dcd_addr DCD loading address
     * @param length Length of DCD
     * @throws IOException If anything goes wrong
     */
    private void sdp_dl_dcd(int dcd_addr, int length) throws IOException {
        /*
         * SDP WRITE DCD
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0a0a       - SDP_WRITE_DCD
         * 0xXXXXXXXX   - address
         * 0x00         - format
         * 0xXXXXXXXX   - count
         * 0x00000000   - value
         * 0x00         - reserved
         */
        byte[] command = Hex.decode("0a0a0000000000000000000000000000");
        Utils.insertIntBE(command,2,dcd_addr);
        Utils.insertIntBE(command,7,length);
        if (device.write(command,command.length, (byte) 0x01) == -1)
            throw new IOException("SDP WRITE DCD failed");
        readToOut(true);
    }

    /**
     * Write file
     *
     * @param dladdr Start address
     * @param fsize Filesize
     * @param type Unknown, should be 0x00
     *
     * @throws IOException If anything goes wrong
     */
    private void sdp_write_file(int dladdr, int fsize, byte type) throws IOException {
        /*
         * SDP WRITE FILE
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0404       - SDP_WRITE_FILE
         * 0xXXXXXXXX   - address
         * 0x00         - format
         * 0xXXXXXXXX   - count
         * 0x00000000   - value
         * 0xXX         - reserved
         */
        byte[] command = Hex.decode("04040000000000000000000000000000");
        Utils.insertIntBE(command,2,dladdr);
        Utils.insertIntBE(command,7,fsize);
        command[15] = type;
        if (device.write(command,command.length, (byte) 0x01) == -1)
            throw new IOException("SDP WRITE FILE failed");
        readToOut(true);
    }

    /**
     * Jump to supplied address and execute
     *
     * @param header_addr Address to jump to
     * @throws IOException If anything goes wrong
     */
    private void sdp_jump(int header_addr) throws IOException {
        /*
         * SDP JUMP
         * 0x01         - 0x11 length command (REPORT ID)
         *
         * 0x0b0b       - SDP_JUMP_ADDRESS
         * 0xXXXXXXXX   - address
         * 0x20         - format
         * 0x00000000   - count
         * 0xXXXXXXXX   - value
         * 0x00         - reserved
         */
        byte[] command = Hex.decode("0b0b0000000000000000000000000000");
        Utils.insertIntBE(command,2,header_addr);
        if (device.write(command,command.length, (byte) 0x01) == -1)
            throw new IOException("SDP JUMP failed");
        readToOut(true);
    }

    /**
     * Write actual data
     *
     * @param data Data to write
     * @throws IOException If anything goes wrong
     */
    private void sdp_data(byte[] data) throws IOException {
        for (byte[] chunk : Utils.divideArray(data,1024)) {
            if (device.write(chunk,chunk.length,(byte)0x02) == -1)
                throw new IOException("Data transfer failed");
            readToOut(true);
        }
    }

    /**
     * Helper function to clear USB buffer, optionally printing its content to stdout
     *
     * @param silent True, to stay silent
     */
    private void readToOut(boolean silent) {
        Byte[] tmp = device.read(1024,200);
        for (Byte b : tmp) {
            if (!silent)
                System.out.print(b & 0xff);
        }
        if (!silent)
            System.out.println();
    }


    @Override
    public void hidDeviceAttached(HidServicesEvent hidServicesEvent) {

    }

    @Override
    public void hidDeviceDetached(HidServicesEvent hidServicesEvent) {

    }

    @Override
    public void hidFailure(HidServicesEvent hidServicesEvent) {
        System.out.println(hidServicesEvent.toString());
    }
}
