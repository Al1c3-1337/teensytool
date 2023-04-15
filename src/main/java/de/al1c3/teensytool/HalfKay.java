package de.al1c3.teensytool;

import org.bouncycastle.util.encoders.Hex;
import org.hid4java.*;
import org.hid4java.event.HidServicesEvent;

import java.io.IOException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@SuppressWarnings("unused")
public class HalfKay implements HidServicesListener {

    private final HidDevice device;
    private final HidServices hidServices;

    /**
     * Create a new HalfKay instance.
     * This tries to connect to the HalfKay Programmer
     *
     * @throws IOException If no HalfKay device is found
     */
    public HalfKay() throws IOException {
        HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
        hidServicesSpecification.setAutoStart(false);
        hidServicesSpecification.setScanMode(ScanMode.SCAN_AT_FIXED_INTERVAL_WITH_PAUSE_AFTER_WRITE);
        hidServices = HidManager.getHidServices(hidServicesSpecification);
        hidServices.start();

        for (HidDevice hidDevice : hidServices.getAttachedHidDevices())
            if (hidDevice.getVendorId() == 0x16c0 && hidDevice.getProductId() == 0x0478) {
                device = hidDevice;
                device.open();
                return;
            }
        throw new IOException("HalfKay not found!");
    }

    /**
     * Close USB connection to HalfKay programmer.
     * This should be done after completing work with this class.
     */
    public void shutdown() {
        hidServices.shutdown();
    }

    /**
     * Send the Teensy flash data
     *
     * @param data The flash data
     * @throws IOException If anything goes wrong
     */
    public void writeData(byte[] data) throws IOException, InterruptedException {
        int addr = 0;
        for (byte[] chunk : Utils.divideArray(data,1024)) {
            byte[] tmp = new byte[chunk.length + 0x40];
            Thread.sleep(addr == 0? 3000 : 200);
            System.arraycopy(chunk,0,tmp,0x40,chunk.length);
            Utils.insertIntLE(tmp,0,addr);
            addr +=chunk.length;
            if (device.write(tmp, tmp.length, (byte) 0x00) == -1)
                throw new IOException("HalfKay write failed " + device.getLastErrorMessage());
        }
    }

    /**
     * Reboot the teensy to load program.
     * Will send a timestamp as well, which can be used to sync the SRTC from teensy code.
     *
     * @param useLocalTime True, to send local time. False, to send UTC.
     * @throws IOException
     * @throws ParseException
     */
    public void reboot(boolean useLocalTime) throws IOException, ParseException {
        long now = useLocalTime ? (LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)) : (System.currentTimeMillis() / 1000L);
        byte[] timeSync = Hex.decode("B731C2890000000000000000");
        Utils.insertIntLE(timeSync,4,(int)(now << 15));
        Utils.insertIntLE(timeSync,8,(int)(now >> 17));
        byte[] rebootChunk = new byte[0x43f];
        rebootChunk[0] = (byte)0xff;
        rebootChunk[1] = (byte)0xff;
        rebootChunk[2] = (byte)0xff;
        System.arraycopy(timeSync,0,rebootChunk,0x40,timeSync.length);
        if (device.write(rebootChunk, rebootChunk.length, (byte) 0xff) == -1)
            throw new IOException("HalfKay reboot failed");
    }

    @Override
    public void hidDeviceAttached(HidServicesEvent hidServicesEvent) {

    }

    @Override
    public void hidDeviceDetached(HidServicesEvent hidServicesEvent) {

    }

    @Override
    public void hidFailure(HidServicesEvent hidServicesEvent) {

    }
}
