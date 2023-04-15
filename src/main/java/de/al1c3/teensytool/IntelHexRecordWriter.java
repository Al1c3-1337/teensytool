/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.al1c3.teensytool;

import java.util.*;

/**
 * Stolen vom GHIDRA
 */
public class IntelHexRecordWriter {

    private final int maxBytesPerLine;

    private int startAddress = 0;

    private int offset = 0;
    private final ArrayList<Byte> bytes = new ArrayList<>();

    private final ArrayList<IntelHexRecord> results = new ArrayList<>();
    private boolean done = false;

    /**
     * Constructor
     *
     * @param maxBytesPerLine the maximum number of bytes to write per line in the hex output
     * remaining bytes will be left out
     */
    public IntelHexRecordWriter(int maxBytesPerLine, int address) {
        if (maxBytesPerLine > IntelHexRecord.MAX_RECORD_LENGTH) {
            throw new IllegalArgumentException("maxBytesPerLine > IntelHexRecord.MAX_RECORD_LENGTH");
        }
        this.maxBytesPerLine = maxBytesPerLine;
        this.startAddress = address;
        results.add(new IntelHexRecord(2, 0, 4, new byte[] {(byte)((startAddress & 0xffff0000) >> 24),(byte)((startAddress & 0xffff0000) >> 16)}));
    }

    public void addByte(byte b) {
        if (done) {
            throw new IllegalStateException("cannot addByte() after finish()");
        }

        bytes.add(b);

        if (bytes.size() >= maxBytesPerLine) {
            emitData();
        }
    }

    private void emitData() {
        final int length = bytes.size();
        if (length > 0) {
            int loadOffset = (int) ((startAddress + offset) & 0x0000ffff);
            byte[] data = new byte[length];
            for (int ii = 0; ii < length; ++ii) {
                data[ii] = bytes.get(ii);
            }
            results.add(new IntelHexRecord(length, loadOffset, 0, data));
            bytes.clear();
            offset+=length;
        }
    }

    public List<IntelHexRecord> finish() {

        // Before finalizing things, write out any remaining bytes that haven't yet been written, if
        // the user has specified to do so via the drop extra bytes option (false =
        // write out everything).
        emitData();

        results.add(new IntelHexRecord(0, 0, 1, new byte[0]));
        done = true;
        return Collections.unmodifiableList(results);
    }
}