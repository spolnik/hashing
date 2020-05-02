package com.hashing;

import java.math.BigInteger;

public class PrettyHash {
    public static String prettify(byte[] hash) {
        final var number = convertToSignumRepresentation(hash);

        return "0x" + addPreceding0sToMakeIt32bit(convertToHex(number));
    }

    private static String addPreceding0sToMakeIt32bit(String hashText) {
        var hashTextBuilder = new StringBuilder(hashText);
        while (hashTextBuilder.length() < 32) {
            hashTextBuilder.insert(0, "0");
        }
        return hashTextBuilder.toString();
    }

    private static String convertToHex(BigInteger number) {
        return number.toString(16);
    }

    private static BigInteger convertToSignumRepresentation(byte[] hash) {
        return new BigInteger(1, hash);
    }
}
