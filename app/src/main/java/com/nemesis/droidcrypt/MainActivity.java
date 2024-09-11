package com.nemesis.droidcrypt;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.bouncycastle.crypto.generators.SCrypt;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private EditText inputEditText, passwordEditText, outputEditText;
    private CheckBox rememberPasswordCheckBox;
    private static final int FILE_PICKER_REQUEST_CODE = 123;
    private static final int PERMISSION_REQUEST_CODE = 124;
    private Uri selectedFileUri;
    private SharedPreferences sharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputEditText = findViewById(R.id.inputEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        outputEditText = findViewById(R.id.outputEditText);
        rememberPasswordCheckBox = findViewById(R.id.rememberPasswordCheckBox);

        // Initialize SharedPreferences
        sharedPreferences = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE);

        // Load saved password if exists
        loadSavedPassword();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, PERMISSION_REQUEST_CODE);
        }
    }

    private void loadSavedPassword() {
        // Load saved password from SharedPreferences
        String savedPassword = sharedPreferences.getString("password", null);
        if (savedPassword != null) {
            passwordEditText.setText(savedPassword);
            rememberPasswordCheckBox.setChecked(true);
        }
    }

    private void savePassword(String password) {
        // Save password to SharedPreferences if "Remember Password" is checked
        if (rememberPasswordCheckBox.isChecked()) {
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putString("password", password);
            editor.apply();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE && (grantResults.length == 0 || grantResults[0] != PackageManager.PERMISSION_GRANTED)) {
            showToast("Permission denied");
        }
    }

    public void pickFile(View view) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, FILE_PICKER_REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_PICKER_REQUEST_CODE && resultCode == Activity.RESULT_OK && data != null) {
            selectedFileUri = data.getData();
            if (selectedFileUri != null) {
                getContentResolver().takePersistableUriPermission(selectedFileUri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                showToast("File selected: " + getFileName(selectedFileUri));
            }
        }
    }

    public void performTextEncryption(View view) {
        processText(true);
    }

    public void performTextDecryption(View view) {
        processText(false);
    }

    private void processText(boolean isEncryption) {
        String inputText = inputEditText.getText().toString();
        if (!inputText.isEmpty()) {
            try {
                String password = passwordEditText.getText().toString();
                savePassword(password); // Save password if "Remember Password" is checked
                String resultText = isEncryption ? encryptText(inputText, password) : decryptText(inputText, password);
                outputEditText.setText(resultText);
            } catch (Exception e) {
                showError((isEncryption ? "Encryption" : "Decryption") + " failed: " + e.getMessage());
            }
        } else {
            showToast("Please enter text to " + (isEncryption ? "encrypt" : "decrypt") + ".");
        }
    }

    public void performFileEncryption(View view) {
        processFile(true);
    }

    public void performFileDecryption(View view) {
        processFile(false);
    }

    private void processFile(boolean isEncryption) {
        if (selectedFileUri != null) {
            String password = passwordEditText.getText().toString();
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                    startActivity(intent);
                    showToast("Please enable the Manage All Files Access permission and try again.");
                    return;
                }

                byte[] processedBytes = isEncryption ? encryptFile(selectedFileUri, password) : decryptFile(selectedFileUri, password);
                if (processedBytes != null) {
                    String fileName = isEncryption ? getFileName(selectedFileUri) + ".enc" : getFileNameWithoutExtension(selectedFileUri);
                    saveFile(processedBytes, fileName);
                    showToast("File " + (isEncryption ? "encrypted" : "decrypted") + " successfully.");
                } else {
                    showError((isEncryption ? "Encryption" : "Decryption") + " failed. Check password or file.");
                }
            } catch (Exception e) {
                showError((isEncryption ? "Encryption" : "Decryption") + " failed: " + e.getMessage());
            }
        } else {
            showToast("Please select a file to " + (isEncryption ? "encrypt" : "decrypt") + ".");
        }
    }

    private void saveFile(byte[] bytes, String fileName) {
        File directory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File file = new File(directory, fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(bytes);
            showToast("File saved as: " + file.getAbsolutePath());
        } catch (IOException e) {
            showError("Failed to save file: " + e.getMessage());
        }
    }

    private byte[] encryptFile(Uri fileUri, String password) throws IOException, GeneralSecurityException {
        try (InputStream inputStream = getContentResolver().openInputStream(fileUri);
             BufferedInputStream bis = new BufferedInputStream(inputStream)) {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] inputBytes = baos.toByteArray();

            byte[] salt = generateSalt();
            SecretKey secretKey = generateSecretKey(password, salt);
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, null);
            byte[] iv = cipher.getIV();
            byte[] cipherText = cipher.doFinal(inputBytes);

            return concatenateArrays(salt, iv, cipherText);
        }
    }

    private byte[] decryptFile(Uri fileUri, String password) throws IOException, GeneralSecurityException {
        try (InputStream inputStream = getContentResolver().openInputStream(fileUri)) {

            byte[] inputBytes = readBytes(inputStream);  // Read entire file (if not large, you can optimize this)
            byte[] salt = Arrays.copyOfRange(inputBytes, 0, 16);
            byte[] iv = Arrays.copyOfRange(inputBytes, 16, 28);
            byte[] cipherText = Arrays.copyOfRange(inputBytes, 28, inputBytes.length);

            SecretKey secretKey = generateSecretKey(password, salt);
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKey, iv);
            return cipher.doFinal(cipherText);
        }
    }

    private String encryptText(String inputText, String password) throws GeneralSecurityException {
        byte[] salt = generateSalt();
        SecretKey secretKey = generateSecretKey(password, salt);
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, null);
        byte[] iv = cipher.getIV();
        byte[] cipherText = cipher.doFinal(inputText.getBytes());
        return Base64.getEncoder().encodeToString(concatenateArrays(salt, iv, cipherText));
    }

    private String decryptText(String inputText, String password) throws GeneralSecurityException {
        byte[] inputBytes = Base64.getDecoder().decode(inputText);
        byte[] salt = Arrays.copyOfRange(inputBytes, 0, 16);
        byte[] iv = Arrays.copyOfRange(inputBytes, 16, 28);
        byte[] cipherText = Arrays.copyOfRange(inputBytes, 28, inputBytes.length);
        SecretKey secretKey = generateSecretKey(password, salt);
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(cipherText));
    }

    private Cipher getCipher(int mode, SecretKey secretKey, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        if (iv == null) {
            cipher.init(mode, secretKey);
        } else {
            cipher.init(mode, secretKey, new GCMParameterSpec(128, iv));
        }
        return cipher;
    }

    private SecretKey generateSecretKey(String password, byte[] salt) throws NoSuchAlgorithmException {
        byte[] derivedKey = SCrypt.generate(password.getBytes(), salt, 32768, 16, 4, 32);
        return new SecretKeySpec(derivedKey, "AES");
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] concatenateArrays(byte[]... arrays) {
        int totalLength = Arrays.stream(arrays).mapToInt(array -> array.length).sum();
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri != null) {
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    result = cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME));
                }
            }
        }
        return result;
    }

    private String getFileNameWithoutExtension(Uri uri) {
        String fileName = getFileName(uri);
        if (fileName != null && fileName.endsWith(".enc")) {
            fileName = fileName.substring(0, fileName.length() - 4);
        }
        return fileName;
    }

    private byte[] readBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];  // Buffer size of 4KB
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byteArrayOutputStream.write(buffer, 0, bytesRead);
        }
        return byteArrayOutputStream.toByteArray();
    }

    public void copyToClipboard(View view) {
        String outputText = outputEditText.getText().toString();
        if (!outputText.isEmpty()) {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("Output Text", outputText);
            if (clipboard != null) {
                clipboard.setPrimaryClip(clip);
                showToast("Output text copied to clipboard.");
            } else {
                showError("Clipboard service not available.");
            }
        } else {
            showToast("Output text is empty.");
        }
    }
    public void forgetEverything(View view) {
        // Clear SharedPreferences
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.remove("password");
        editor.apply();

        passwordEditText.setText(""); // Clear the password EditText
        // Clear input and output fields
        inputEditText.setText("");
        outputEditText.setText("");

        // Clear remember password checkbox
        rememberPasswordCheckBox.setChecked(false);

        showToast("All data forgotten.");
    }

    public void pasteInput(View view) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null && clipboard.hasPrimaryClip()) {
            ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
            CharSequence pasteData = item.getText();
            if (pasteData != null) {
                inputEditText.setText(pasteData.toString());
                showToast("Pasted text successfully.");
            } else {
                showToast("Clipboard contains no data to paste.");
            }
        } else {
            showToast("Clipboard is empty.");
        }
    }

    private void showToast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private void showError(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }
}
