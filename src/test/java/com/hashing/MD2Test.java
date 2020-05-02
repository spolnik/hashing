package com.hashing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static com.hashing.PrettyHash.prettify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class MD2Test {

    private HashFunction md2 = new MD2();
    private MessageDigest md2Java;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        md2Java = MessageDigest.getInstance("MD2");
    }

    @Test
    void generates_md2_hash() {
        var input = "Hello, World!".getBytes();

        var result = md2.hash(input);
        assertThat(prettify(result))
                .isEqualTo(prettify(md2Java.digest(input)));
    }

    @Test
    void reruns_of_md2_hash_gives_same_result() {
        var input = "".getBytes();

        var result = md2.hash(input);

        assertThat(result)
                .isEqualTo(md2.hash(input));
    }

    @Test
    void returns_md2_hash_from_empty_input() {
        var result = md2.hash(new byte[0]);

        assertThat(prettify(result))
                .isEqualTo("0x8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    void throws_if_input_null() {
        assertThatThrownBy(() -> md2.hash(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("input is null");
    }

    @ParameterizedTest
    @MethodSource("standardMD2TestDeck")
    void returns_md2_hash_for(String input, String expected) {
        var result = md2.hash(input.getBytes());

        assertThat(prettify(result))
                .isEqualTo(expected);
    }

    static Stream<Arguments> standardMD2TestDeck() {
        return Stream.of(
                arguments("", "0x8350e5a3e24c153df2275c9f80692773"),
                arguments("a", "0x32ec01ec4a6dac72c0ab96fb34c0b5d1"),
                arguments("abc", "0xda853b0d3f88d99b30283a69e6ded6bb"),
                arguments("message digest", "0xab4f496bfb2a530b219ff33031fe06b0"),
                arguments("abcdefghijklmnopqrstuvwxyz", "0x4e8ddff3650292ab5a4108c3aa47940b"),
                arguments("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                        "0xda33def2a42df13975352846c30338cd"),
                arguments("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                        "0xd5976f79d83d3a0dc9806c3c66f3efd8")
        );
    }
}