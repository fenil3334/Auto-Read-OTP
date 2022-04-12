package com.mktech.autoverifyotpandroid;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.stfalcon.smsverifycatcher.OnSmsCatchListener;
import com.stfalcon.smsverifycatcher.SmsVerifyCatcher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {
    private SmsVerifyCatcher smsVerifyCatcher;
    private static final String HASH_TYPE = "SHA-256";
    public static final int NUM_HASHED_BYTES = 9;
    public static final int NUM_BASE64_CHAR = 11;
    EditText etCode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


          etCode = (EditText) findViewById(R.id.et_code);
        final Button btnVerify = (Button) findViewById(R.id.btn_verify);

        //init SmsVerifyCatcher
        smsVerifyCatcher = new SmsVerifyCatcher(this, new OnSmsCatchListener<String>() {
            @Override
            public void onSmsCatch(String message) {
                String code = parseCode(message);//Parse verification code
                Log.e("OTP","----->"+code);
                etCode.setText(code);//set code in edit text
                //then you can send verification code to server
            }
        });

        //set phone number filter if needed
        smsVerifyCatcher.setPhoneNumberFilter("756");
        //smsVerifyCatcher.setFilter("regexp");

        //button for sending verification code manual
        btnVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //send verification code to server
            }
        });

        //461CtBufelM
     /*   getAppSignatures();
        getOTP(this,7);*/
        readOTP();
    }




    private void readOTP()
    {
        SmsReceiver.bindListener(new SmsListener()
        {
            @Override
            public void messageReceived(String messageText)
            {
                Log.e("OTPMESSAGE","---------------->"+messageText);
                etCode.setText(messageText);

                //Note: "edt_verify_otp" is your Editext Object.
            }
        });
    }



    @TargetApi(Build.VERSION_CODES.M)
    static void getOTP(final Activity mActivity, final int PERMISSION_REQUEST_CODE)
    {
        List<String> permissionsNeeded = new ArrayList<>();

        List<String> permissionsList = new ArrayList<>();

        if (!addPermission(mActivity,permissionsList, android.Manifest.permission.READ_SMS))
            permissionsNeeded.add("REAL SMS");


        if (permissionsList.size() > 0)
        {
            mActivity.requestPermissions(permissionsList.toArray(new String[permissionsList.size()]), PERMISSION_REQUEST_CODE);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static boolean addPermission(Context context, List<String> permissionsList, String permission)
    {
        if (context.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED)
        {
            permissionsList.add(permission);

            return false;
        }
        return true;
    }



    /**
     * Parse verification code
     *
     * @param message sms message
     * @return only four numbers from massage string
     */
    private String parseCode(String message) {
        Pattern p = Pattern.compile("\\b\\d{4}\\b");
        Matcher m = p.matcher(message);
        String code = "";
        while (m.find()) {
            code = m.group(0);
        }
        return code;
    }

    @Override
    protected void onStart() {
        super.onStart();
        smsVerifyCatcher.onStart();
    }

    @Override
    protected void onStop() {
        super.onStop();
        smsVerifyCatcher.onStop();
    }

    /**
     * need for Android 6 real time permissions
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        smsVerifyCatcher.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }



    public List<String> getAppSignatures() {
        ArrayList<String> appCodes = new ArrayList<>();
        String packageName = getPackageName();
        try {// Get all package signatures for the current package
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                SigningInfo sig = getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo;
                if (sig.hasMultipleSigners()) // Send all with apkContentsSigners
                    return getAppCodes(sig.getApkContentsSigners(), packageName);
                else
                    return getAppCodes(sig.getSigningCertificateHistory(), packageName);
            } else {
                PackageInfo packageInfo = getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                Signature[] signatures = packageInfo.signatures;
                return getAppCodes(signatures, packageName);
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e("TAG", "Unable to find package to obtain hash.", e);
        }
        return appCodes;
    }

    private static List<String> getAppCodes(Signature[] signatures, String packageName) {
        List<String> appCodes = new ArrayList<>();
        // For each signature create a compatible hash
        for (Signature signature : signatures) {
            String hash = hash(packageName, signature.toCharsString());
            if (hash != null)
                appCodes.add(String.format("%s", hash));
            Log.v("OTP", "Hash " + hash);
        }
        return appCodes;
    }

    private static String hash(String packageName, String signature) {
        String appInfo = packageName + " " + signature;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(HASH_TYPE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT)
                messageDigest.update(appInfo.getBytes(StandardCharsets.UTF_8));
            byte[] hashSignature = messageDigest.digest();
            hashSignature = Arrays.copyOfRange(hashSignature, 0, NUM_HASHED_BYTES);// truncated into NUM_HASHED_BYTES
            String base64Hash = Base64.encodeToString(hashSignature, Base64.NO_PADDING | Base64.NO_WRAP);// encode into Base64
            base64Hash = base64Hash.substring(0, NUM_BASE64_CHAR);
            Log.d("OTP","========>"+base64Hash);
            Log.d("OTP", String.format("pkg: %s -- hash: %s", packageName, base64Hash));
            return base64Hash;
        } catch (NoSuchAlgorithmException e) {
            Log.e("OTP", "hash:NoSuchAlgorithm", e);
        }
        return null;
    }
}