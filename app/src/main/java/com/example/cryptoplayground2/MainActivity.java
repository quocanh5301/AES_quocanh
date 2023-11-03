package com.example.cryptoplayground2;

import static com.example.cryptoplayground2.QAData.SBox;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

//2/11
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity{
    private static String TAG = "CryptoAssignment";

    List<String> roundKeys;
    QAData data;

    private void testFunc(){
        data.MixColumns(data.paddedPlaintext);
        Log.i(TAG, "MixColumns: " + Arrays.toString(data.currState));
        data.InverseMixColumns(data.currState);
        Log.i(TAG, "InverseMixColumns: " + Arrays.toString(data.currState));

        data.SubBytes(data.paddedPlaintext);
        Log.i(TAG, "SubBytes: " + Arrays.toString(data.currState));
        data.InverseSubBytes(data.currState);
        Log.i(TAG, "InverseSubBytes: " + Arrays.toString(data.currState));

        data.ShiftRows(data.paddedPlaintext);
        Log.i(TAG, "ShiftRows: " + Arrays.toString(data.currState));
        data.InverseShiftRows(data.currState);
        Log.i(TAG, "InverseShiftRows: " + Arrays.toString(data.currState));
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        cbcTest2();
    }

    public void cbcTest2(){
        data = new QAData(null, hexStringToByteArray("28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"));
        String keyHex = "140b41b22a29beb4061bda66b6747e14"; // 128-bit key in hex
//        data.plaintext = hexStringToByteArray("28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
        Log.i(TAG, "cbcTest2: original size " + Arrays.toString(data.plaintext).length());
        data.paddingPlainText();
        Log.i(TAG, "cbcTest2: padded " + Arrays.toString(data.paddedPlaintext));
        data.inversePadding();
        Log.i(TAG, "cbcTest2: original " + Arrays.toString(data.plaintext));

        String fullCipher = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        String ciphertext = getcipherFromFullCipher(fullCipher);
        System.out.println("Encrypted Text (Hex): " + ciphertext);

        String iv = getIVFromFullCipher(fullCipher);
        System.out.println("IV: " + iv);

//        byte[] key = hexStringToByteArray(keyHex);
        byte[] ivByte = hexStringToByteArray(iv);

        testFunc();

//        roundKeys = expandKey(hexStringToByteArray(keyHex));
//        for (int i = 0; i < roundKeys.size(); i++){
//            Log.i(TAG, "cbcTest2: round key " + i + " " +roundKeys.get(i));
//        }



        // Decrypt the ciphertext
//        byte[] decryptedPlaintext = new byte[0];
//        try {
//            decryptedPlaintext = decryptAES(hexStringToByteArray(keyHex), ivByte);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//
//        // Convert the decrypted plaintext to a hex format
//        String decryptedPlaintextHex = byteArrayToHexString(decryptedPlaintext);
//        System.out.println("Decrypted Plaintext: " + decryptedPlaintextHex);
    }

//qa 1

//        public static byte[] encryptAES(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
//            int blockSize = 16;
//            int paddingLength = blockSize - (plaintext.length % blockSize);
//
//            // Add PKCS7 padding to plaintext
//            byte[] paddedPlaintext = Arrays.copyOf(plaintext, plaintext.length + paddingLength);
//            Arrays.fill(paddedPlaintext, plaintext.length, paddedPlaintext.length, (byte) paddingLength);
//
//            // Initialize the IV
//            byte[] prevCipherBlock = iv;
//
//            // Initialize the ciphertext
//            byte[] ciphertext = new byte[paddedPlaintext.length];
//
//            // Iterate over blocks
//            for (int i = 0; i < paddedPlaintext.length; i += blockSize) {
//                // XOR the plaintext block with the previous ciphertext block (or IV for the first block)
//                for (int j = 0; j < blockSize; j++) {
//                    paddedPlaintext[i + j] ^= prevCipherBlock[j];
//                }
//
//                // Apply AES operations (SubBytes, ShiftRows, MixColumns, and AddRoundKey)
//                qaSubBytes(paddedPlaintext, i);
//                ShiftRows(paddedPlaintext, i);
//                MixColumns(paddedPlaintext, i);
//
//                // Encrypt the block with AES ECB mode
//                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
//                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
//                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//                byte[] blockCipher = cipher.doFinal(Arrays.copyOfRange(paddedPlaintext, i, i + blockSize));
//
//                // Set the current ciphertext block
//                for (int j = 0; j < blockSize; j++) {
//                    ciphertext[i + j] = blockCipher[j];
//                }
//
//                // Update the previous ciphertext block
//                prevCipherBlock = blockCipher;
//            }
//            return ciphertext;
//        }

    public byte[] decryptAES(byte[] key, byte[] iv) throws Exception {
        roundKeys = expandKey(key);
        byte[] decryptedPlaintext = new byte[data.ciphertext.length];

        for (data.ROUND = 10; data.ROUND >= 0; data.ROUND--){
            if (data.ROUND != 10 && data.ROUND != 0){
                data.addRoundKey(data.paddedPlaintext, hexStringToByteArray(roundKeys.get(data.ROUND)));
                data.InverseMixColumns(data.paddedPlaintext);
                data.InverseShiftRows(data.paddedPlaintext);
                data.InverseSubBytes(data.paddedPlaintext);
                data.currState = xorByteArrays(data.previousState, data.currState);
            } else if (data.ROUND == 10) {
                data.addRoundKey(data.paddedPlaintext, hexStringToByteArray(roundKeys.get(10)));
                data.InverseShiftRows(data.paddedPlaintext);
                data.InverseSubBytes(data.paddedPlaintext);
            } else  {
                data.addRoundKey(data.paddedPlaintext, hexStringToByteArray(roundKeys.get(1)));
            }

        }

        data.ROUND = 0;
        return decryptedPlaintext;
    }


    public static List<String> expandKey(byte[] key) {
        int keySize = 16; // AES-128
        int numRounds = 10;
        int expandedKeySize = 176; // 16 bytes for the original key + 16 bytes per round key

        // Ensure the input key is of the correct size (128 bits)
        if (key.length != keySize) {
            throw new IllegalArgumentException("AES-128 key must be 16 bytes in length.");
        }

        // The expanded key will contain the original key followed by round keys
        byte[] expandedKey = new byte[expandedKeySize];
        System.arraycopy(key, 0, expandedKey, 0, keySize);

        // Perform key expansion
        for (int round = 1; round <= numRounds; round++) {
            byte[] temp = new byte[4];
            System.arraycopy(expandedKey, (round - 1) * 4, temp, 0, 4);

            // Apply key schedule core (rotate, substitute, and XOR with round constant)
            temp = keyScheduleCore(temp, round);

            // XOR the result with the key schedule of the previous round
            for (int i = 0; i < 4; i++) {
                expandedKey[round * 16 + i] = (byte) (expandedKey[(round - 1) * 16 + i] ^ temp[i]);
            }

            // For the remaining 12 bytes in the block, just XOR with the previous round key
            for (int j = 1; j < 4; j++) {
                for (int i = 0; i < 4; i++) {
                    expandedKey[round * 16 + (j * 4) + i] = (byte) (expandedKey[round * 16 + ((j - 1) * 4) + i] ^ expandedKey[(round - 1) * 16 + (j * 4) + i]);
                }
            }
        }

        // Convert the expanded key to a list of 16-byte hexadecimal strings
        List<String> roundKeys = new ArrayList<>();
        for (int i = 0; i < expandedKeySize; i += keySize) {
            roundKeys.add(bytesToHex(Arrays.copyOfRange(expandedKey, i, i + keySize)));
        }

        return roundKeys;
    }

    private static byte[] keyScheduleCore(byte[] input, int round) {
        // Rotate the input
        byte[] output = new byte[input.length];
        System.arraycopy(input, 1, output, 0, 3);
        output[3] = input[0];

        // Substitute bytes
        for (int i = 0; i < 4; i++) {
            output[i] = KeySubBytes(output[i]);
        }

        // XOR with round constant
        output[0] ^= getRoundConstant(round);

        return output;
    }

    private static byte KeySubBytes(byte input) {
        // This function performs the SubBytes operation using an S-box.
        int row = (input >> 4) & 0x0F;
        int col = input & 0x0F;
        return (byte) SBox[row][col];
    }

    private static byte getRoundConstant(int round) {
        // This function returns the round constant for the given round.
        return (byte) (1 << (round - 1));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

//qa 2

    public static String getIVFromFullCipher(String fullCipher) {
        return fullCipher.substring(0, 32).trim();
    }

    public static String getcipherFromFullCipher(String fullCipher) {
        return fullCipher.substring(32).trim();
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] xorByteArrays(byte[] array1, byte[] array2) {
        int length = Math.min(array1.length, array2.length);
        byte[] result = new byte[length];

        for (int i = 0; i < length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }

}


