package com.hashing;

import java.security.DigestException;
import java.security.ProviderException;
import java.util.Arrays;

import static java.lang.System.arraycopy;
import static java.util.Objects.requireNonNull;

/**
 * https://tools.ietf.org/html/rfc1319
 */
public class MD2 implements HashFunction {

    private static final int BLOCK_SIZE_16 = 16;
    private static final int DIGEST_LENGTH_16 = 16;

    private int[] X = new int[48];

    // checksum, 16 ints. they are really bytes, but byte arithmetic in the JVM is much slower that int arithmetic.
    private int[] C = new int[BLOCK_SIZE_16];

    // temporary store for checksum C during final digest
    private byte[] cBytes = new byte[BLOCK_SIZE_16];

    // buffer to store partial blocks, blockSize bytes large
    // Subclasses should not access this array directly except possibly in their
    // implDigest() method. See MD5.java as an example.
    byte[] buffer = new byte[BLOCK_SIZE_16];
    // offset into buffer
    private int bufOfs;
    // number of bytes processed so far
    // also used as a flag to indicate reset status
    // -1: need to call reset() before next call to update()
    //  0: is already reset
    long bytesProcessed;

    @Override
    public byte[] hash(byte[] input) {
        requireNonNull(input, "input is null");
        appendChecksum(input, input.length);
        return hash();
    }

    private byte[] hash() {
        var b = new byte[DIGEST_LENGTH_16];
        try {
            startHashing(b, b.length);
        } catch (DigestException e) {
            throw new ProviderException("Internal error", e);
        }
        return b;
    }

    private void startHashing(byte[] out, int len) throws DigestException {
        if (len < DIGEST_LENGTH_16) {
            throw new DigestException("Length must be at least "
                    + DIGEST_LENGTH_16 + " for MD2 hash");
        }
        if (0 > out.length - len) {
            throw new DigestException("Buffer too short to store digest");
        }
        if (bytesProcessed < 0) {
            reset();
        }
        internalHash(out);
        bytesProcessed = -1;
    }

    private void internalHash(byte[] out) {
        var padValue = 16 - ((int)bytesProcessed & 15);
        appendChecksum(PADDING[padValue], padValue);
        for (var i = 0; i < 16; i++) {
            cBytes[i] = (byte)C[i];
        }
        compress(cBytes, 0);
        for (var i = 0; i < 16; i++) {
            out[i] = (byte)X[i];
        }
    }

    private void appendChecksum(byte[] b, int len) {
        var ofs = 0;
        if (len == 0) {
            return;
        }
        if (bytesProcessed < 0) {
            reset();
        }
        bytesProcessed += len;
        // if buffer is not empty, we need to fill it before proceeding
        if (bufOfs != 0) {
            var n = Math.min(len, BLOCK_SIZE_16 - bufOfs);
            arraycopy(b, ofs, buffer, bufOfs, n);
            bufOfs += n;
            ofs += n;
            len -= n;
            if (bufOfs >= BLOCK_SIZE_16) {
                // compress completed block now
                compress(buffer, 0);
                bufOfs = 0;
            }
        }
        // compress complete blocks
        if (len >= BLOCK_SIZE_16) {
            var limit = ofs + len;
            ofs = compressMultiBlock(b, ofs, limit - BLOCK_SIZE_16);
            len = limit - ofs;
        }
        // copy remainder to buffer
        if (len > 0) {
            arraycopy(b, ofs, buffer, 0, len);
            bufOfs = len;
        }
    }

    // compress complete blocks
    private int compressMultiBlock(byte[] b, int ofs, int limit) {
        compressMultiBlockCheck(b, ofs, limit);
        return implCompressMultiBlock0(b, ofs, limit);
    }

    private void compressMultiBlockCheck(byte[] b, int ofs, int limit) {
        if (limit < 0) {
            // not an error because compressMultiBlockImpl won't execute if limit < 0, and an exception is thrown if ofs < 0.
            return;
        }
        requireNonNull(b);

        if (ofs < 0 || ofs >= b.length) {
            throw new ArrayIndexOutOfBoundsException(ofs);
        }

        var endIndex = (limit / BLOCK_SIZE_16) * BLOCK_SIZE_16 + BLOCK_SIZE_16 - 1;
        if (endIndex >= b.length) {
            throw new ArrayIndexOutOfBoundsException(endIndex);
        }
    }

    private int implCompressMultiBlock0(byte[] b, int ofs, int limit) {
        for (; ofs <= limit; ofs += BLOCK_SIZE_16) {
            compress(b, ofs);
        }
        return ofs;
    }

    private void reset() {
        if (bytesProcessed == 0) {
            // already reset, ignore
            return;
        }
        Arrays.fill(X, 0);
        Arrays.fill(C, 0);
        bufOfs = 0;
        bytesProcessed = 0;
        Arrays.fill(buffer, (byte) 0x00);
    }

    private void compress(byte[] b, int ofs) {
        for (var i = 0; i < 16; i++) {
            var k = b[ofs + i] & 0xff;
            X[16 + i] = k;
            X[32 + i] = k ^ X[i];
        }

        // update the checksum
        var t = C[15];
        for (var i = 0; i < 16; i++) {
            t = (C[i] ^= S[X[16 + i] ^ t]);
        }

        t = 0;
        for (var i = 0; i < 18; i++) {
            for (var j = 0; j < 48; j++) {
                t = (X[j] ^= S[t]);
            }
            t = (t + i) & 0xff;
        }
    }

    // substitution table derived from Pi. Copied from the RFC.
    private static final int[] S = new int[] {
            41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
            19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
            76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
            138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
            245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
            148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
            39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
            181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
            150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
            112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
            96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
            85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
            234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
            129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
            8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
            203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
            166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
            31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
    };

    // digest padding. 17 element array.
    // padding[0] is null
    // padding[i] is an array of i time the byte value i (i = 1..16)
    private static final byte[][] PADDING;

    static {
        PADDING = new byte[17][];
        for (var i = 1; i < 17; i++) {
            var b = new byte[i];
            Arrays.fill(b, (byte)i);
            PADDING[i] = b;
        }
    }
}
