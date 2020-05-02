package com.hashing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.hashing.PrettyHash.prettify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    void returns_md2_hash_from_empty_string() {
        var input = "".getBytes();

        var result = md2.hash(input);

        assertThat(prettify(result))
                .isEqualTo("0x8350e5a3e24c153df2275c9f80692773");
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
}