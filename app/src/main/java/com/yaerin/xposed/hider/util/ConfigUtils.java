package com.yaerin.xposed.hider.util;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.yaerin.xposed.hider.BuildConfig;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Set;

import de.robv.android.xposed.XposedBridge;

/**
 * Create by Yaerin on 2018/6/23
 *
 * @author Yaerin
 */
public class ConfigUtils {

    private static final String PATH = "rules";
    private static final String FILE = "list.json";
    private static boolean chmod=false;

    public static void put(Context context, Set<String> apps) {
        File path = context.getDir(PATH, Context.MODE_PRIVATE);
        File file = new File(path, FILE);
        if (!path.exists()) {
            path.mkdirs();
            setFilePermissions(path, 0777, -1, -1);
        }
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(new Gson().toJson(apps).getBytes());
            fos.close();
            setFilePermissions(file, 0777, -1, -1);
        } catch (IOException e) {
            Log.i("Xposed", Log.getStackTraceString(e));
        }
    }

    public static Set<String> get() {
        StringBuilder s = new StringBuilder();
        String file_path="/data/data/" + BuildConfig.APPLICATION_ID + "/app_rules";
        String fi=file_path+"/"+FILE;

        if (chmod){
            chmod=true;
            Process process = null;
            DataOutputStream dataOutputStream = null;

            try {
                process = Runtime.getRuntime().exec("su");
                dataOutputStream = new DataOutputStream(process.getOutputStream());
                dataOutputStream.writeBytes("chmod 777 "+fi+"\n");
                dataOutputStream.writeBytes("exit\n");
                dataOutputStream.flush();
                process.waitFor();
            } catch (Exception e) {

            } finally {
                try {
                    if (dataOutputStream != null) {
                        dataOutputStream.close();
                    }
                    process.destroy();
                } catch (Exception e) {
                }
            }
        }



        File path = new File(file_path);
//        Log.i("Xposed", "[W/XposedHider] " + path.exists());
        File file = new File(path, FILE);
//        int code=setFilePermissions(file, 0777, -1, -1);
        Log.i("Xposed", "[W/XposedHider] " + file.exists()+file.canRead());
        if (file.exists() && file.canRead()) {
            try {
                InputStreamReader isr = new InputStreamReader(new FileInputStream(file));
                BufferedReader bufReader = new BufferedReader(isr);
                String line;
                while ((line = bufReader.readLine()) != null) {
                    s.append("\n").append(line);
                }
                bufReader.close();
                isr.close();
            } catch (Exception e) {
                Log.i("Xposed", Log.getStackTraceString(e));
            }
        } else {
            String t = file.exists() ? "Cannot read config file." : "Config file does not exists.";
            Log.i("Xposed", "[W/XposedHider] " + t);
        }
        return new Gson().fromJson(s.toString(), new TypeToken<Set<String>>() {
        }.getType());
    }

    @SuppressLint("PrivateApi")
    public static int setFilePermissions(File path, int chmod, int uid, int gid) {
        Class<?> cls;
        try {
            cls = Class.forName("android.os.FileUtils");
            Method method = cls.getMethod("setPermissions", File.class, int.class, int.class, int.class);
            return (int) method.invoke(null, path, chmod, uid, gid);
        } catch (Exception e) {
            Log.i("Xposed", Log.getStackTraceString(e));
            return 1;
        }
    }
}
