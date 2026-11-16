package com.sslsupport.plugin;

import android.os.Bundle;
import android.content.Context;
import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import android.webkit.URLUtil;
import android.webkit.WebSettings;
import android.webkit.WebView;

import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;

//import okhttp3.OkHttpClient;
//import okhttp3.Request;
//import okhttp3.Response;
//import okhttp3.HttpUrl;
//import okhttp3.FormBody;
//import okhttp3.RequestBody;
//import okhttp3.CertificatePinner;

import okhttp3.*;
import com.thomasbouvier.persistentcookiejar.*; //for persistentcookiejar
import com.thomasbouvier.persistentcookiejar.cache.*;
import com.thomasbouvier.persistentcookiejar.persistence.*;

import java.io.IOException;
import java.io.BufferedInputStream;

import java.net.URI;
import android.content.SharedPreferences;

//import java.util.Map;
//import java.util.HashMap;
import android.util.Log;

import androidx.annotation.NonNull;

import java.util.*;
import java.util.concurrent.TimeUnit;

import java.io.InputStream;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okio.Buffer;
import okio.BufferedSink;
import okio.BufferedSource;
import okio.ByteString;
import okio.ForwardingSource;
import okio.Okio;
import okio.Source;

//import com.wallethub.plugin.OkHttpCertPin;

/**
 * This class echoes a string called from JavaScript.
 */
public class CordovaPluginSslSupport extends CordovaPlugin {

    private static class ProgressResponseBody extends ResponseBody {

        private final ResponseBody responseBody;
        private final ProgressListener progressListener;
        private BufferedSource bufferedSource;

        ProgressResponseBody(ResponseBody responseBody, ProgressListener progressListener) {
            this.responseBody = responseBody;
            this.progressListener = progressListener;
        }

        @Override
        public MediaType contentType() {
            return responseBody.contentType();
        }

        @Override
        public long contentLength() {
            return responseBody.contentLength();
        }

        @NonNull
        @Override
        public BufferedSource source() {
            if (bufferedSource == null) {
                bufferedSource = Okio.buffer(source(responseBody.source()));
            }
            return bufferedSource;
        }

        private Source source(Source source) {
            return new ForwardingSource(source) {
                long totalBytesRead = 0L;

                @Override
                public long read(@NonNull Buffer sink, long byteCount) throws IOException {
                    long bytesRead = super.read(sink, byteCount);
                    // read() returns the number of bytes read, or -1 if this source is exhausted.
                    totalBytesRead += bytesRead != -1 ? bytesRead : 0;
                    progressListener.update(totalBytesRead, responseBody.contentLength(), bytesRead == -1);
                    return bytesRead;
                }
            };
        }
    }

    interface ProgressListener {
        void update(long bytesRead, long contentLength, boolean done);
    }

    public WebSettings settings;

    // Context context=this.cordova.getActivity().getApplicationContext();
    // ClearableCookieJar cookieJar = new PersistentCookieJar(new SetCookieCache(),
    // new SharedPrefsCookiePersistor(context));
    // private PersistentCookieJar persistentCookieJar;
    CallbackContext PUBLIC_CALLBACKS = null;

    // The jar given to OkHttp (wraps persistentCookieJar, see SessionAwareCookieJar)
    ClearableCookieJar cookieJar;
    // The library jar. Its methods synchronize on it, so the cookie code below locks it too.
    PersistentCookieJar persistentCookieJar;
    // Kept so the cookie methods can read and remove single cookies (PersistentCookieJar only exposes clear-all)
    SetCookieCache cookieCache;
    SharedPrefsCookiePersistor cookiePersistor;

    // Fixes a gap in PersistentCookieJar: when a response replaces a persistent cookie with a session cookie
    // of the same identity, the library updates its in-memory cache but leaves the old persistent copy on
    // disk. After an app restart that stale copy is loaded again and sent to the server.
    // This wrapper deletes the on-disk copy whenever a session cookie is received.
    private static final class SessionAwareCookieJar implements ClearableCookieJar {
        private final PersistentCookieJar delegate;
        private final CookiePersistor persistor;

        SessionAwareCookieJar(PersistentCookieJar delegate, CookiePersistor persistor) {
            this.delegate = delegate;
            this.persistor = persistor;
        }

        @Override
        public void saveFromResponse(@NonNull HttpUrl url, @NonNull List<Cookie> cookies) {
            synchronized (delegate) {
                delegate.saveFromResponse(url, cookies);
                List<Cookie> sessionCookies = new ArrayList<>();
                for (Cookie cookie : cookies) {
                    if (!cookie.persistent()) {
                        sessionCookies.add(cookie);
                    }
                }
                if (!sessionCookies.isEmpty()) {
                    persistor.removeAll(sessionCookies);
                }
            }
        }

        @NonNull
        @Override
        public List<Cookie> loadForRequest(@NonNull HttpUrl url) {
            return delegate.loadForRequest(url);
        }

        @Override
        public void clearSession() {
            delegate.clearSession();
        }

        @Override
        public void clear() {
            delegate.clear();
        }
    }

    Activity activity;
    ApplicationInfo appliInfo = null;

    Boolean SSL_PINNING_STATUS = false; // flag to know whether the certificates have been pinned or not
    Boolean SSL_PINNING_STOP = false; // force stop pinning, and remove cert pinner
    Boolean OKHTTPCLIENT_INIT = false;

    String newurl = "";

    public CertificatePinner getPinnedHashes() {
        CertificatePinner.Builder builder = new CertificatePinner.Builder();
        Activity activity = this.cordova.getActivity();
        try {
            appliInfo = activity.getPackageManager().getApplicationInfo(activity.getPackageName(),
                    PackageManager.GET_META_DATA);
        } catch (NameNotFoundException e) {
            Log.e("SSLpinning", "NameNotFoundException+" + e.getMessage());
        }
        Bundle bundle = appliInfo.metaData;
        try {

            for (String key : bundle.keySet()) {
                String val = bundle.get(key).toString();
                String[] vals = val.split(",");
                for (int i = 0; i < vals.length; i++) {
                    builder.add(key, "sha256/" + vals[i]);
                    Log.i("SSLpinning", key + "=" + "sha256/" + vals[i]);
                }
            }
        } catch (IllegalArgumentException e) {
            // do something
            Log.e("SSLpinning", "IllegalArgumentException+" + e.getMessage());
        } catch (Exception e) {
            // do something
            Log.e("SSLpinning", "Exception+" + e.getMessage());
        }

        return builder.build();
    }

    OkHttpClient client = getOkHttpClient(); // new OkHttpClient();
    // OkHttpClient client = new OkHttpClient.Builder().build();
    OkHttpClient httpclient = getOkHttpClient();

    ArrayList<String> domainlist = new ArrayList<>(); // saves all secure domains

    public OkHttpClient getOkHttpClient() {

        try {
            return new OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .writeTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .build();
        } catch (Exception e) {
            // do something
            Log.e("SSLpinning", "getclientException+" + e.getMessage());
        }

        return new OkHttpClient();
    }

    // ######################Main Execute function
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        PUBLIC_CALLBACKS = callbackContext;

        JSONObject retObj = new JSONObject();

        if (action.equals("get") || action.equals("post") || action.equals("download") || action.equals("put")
                || action.equals("delete")) {
            try {
                try {
                    this.getpostMethod(action, args, callbackContext);

                } catch (NullPointerException e) {
                    retObj.put("data", "");
                    retObj.put("httperrorcode", 0);
                    retObj.put("errorcode", -3);
                    retObj.put("errorinfo", e.getMessage());
                    callbackContext.error(retObj);

                    return false;
                } catch (Exception e) {
                    retObj.put("data", "");
                    retObj.put("httperrorcode", 0);
                    retObj.put("errorcode", -2);
                    retObj.put("errorinfo", e.getMessage());
                    callbackContext.error(retObj);
                    return false;
                }
            } catch (JSONException e) {
                callbackContext.error("JSONerror=" + e.getMessage());
            }
            return true;
        } else if (action.equals("getCookies")) {
            try {
                this.getCookies(args, callbackContext);

            } catch (Exception e) {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        } else if (action.equals("clearCookies")) {
            try {
                this.clearCookies(args, callbackContext);
            } catch (Exception e) {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        } else if (action.equals("clearAllCookies")) {
            try {
                this.clearAllCookies(args, callbackContext);
            } catch (Exception e) {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        } else if(action.equals("setRequestTimeout")) {
            try{
                this.setRequestTimeout(args, callbackContext);
            } catch (Exception e)
            {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        } else if (action.equals("enableSSLPinning")) {
            try {
                this.enableSSLPinning(args, callbackContext);

            } catch (Exception e) {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        } else if (action.equals("cancelRequest")) {
            try {
                String urlkey = args.getString(0);
                OkHttpUtils.cancelCallWithTag(client, urlkey);
                OkHttpUtils.cancelCallWithTag(httpclient, urlkey);
                callbackContext.success("done");

            } catch (Exception e) {
                callbackContext.error(e.getMessage());
                return false;
            }
            return true;
        }

        return false;
    }

    // #######################Initialize

    public void initialize(final CordovaInterface cordova, final CordovaWebView webView) {
        super.initialize(cordova, webView);
        // try{

        // settings = ((WebView) webView.getEngine().getView()).getSettings();

        // }catch (Exception error){

        // settings = null;

        // }

        activity = cordova.getActivity();
        Context context = activity.getApplicationContext();

        try {
            settings = ((WebView) webView.getEngine().getView()).getSettings();
        } catch (Exception error) {
            // settings = null;
            // if the above fails then use the one below
            settings = new WebView(activity.getApplicationContext()).getSettings();
        }

        if (!OKHTTPCLIENT_INIT) {
            Log.i("SSLpinning", "OKHTTPCLIENT_INIT: Done");

            cookieCache = new SetCookieCache();
            cookiePersistor = new SharedPrefsCookiePersistor(context);
            persistentCookieJar = new PersistentCookieJar(cookieCache, cookiePersistor);
            cookieJar = new SessionAwareCookieJar(persistentCookieJar, cookiePersistor);
            httpclient = httpclient.newBuilder()
                    .cookieJar(cookieJar)
                    .build();
            client = client.newBuilder()
                    .cookieJar(cookieJar)
                    .build();

            OKHTTPCLIENT_INIT = true;

        }
    }

    // ########### Cookies
    // Kept in step with the iOS implementation (sslsupport.m): same arguments, filtering and result shape.
    // The plugin's cookie store is the OkHttp jar; it is not shared with the WebView.

    // getCookies(domainFilter)
    // args[0] (optional): "all" (default) or a substring the cookie domain must contain.
    // Returns { <name>: { name, value, domain, path, expires, secure, httpOnly, version } } for unexpired cookies,
    // session cookies included. expires is seconds since epoch, 0 for session cookies.
    private void getCookies(JSONArray args, CallbackContext callbackContext) throws JSONException {
        String domainFilter = domainFilterFromArgs(args, 0);
        long now = System.currentTimeMillis();
        JSONObject result = new JSONObject();

        // the cache is what requests are sent from: it holds session cookies (never persisted) and persistent ones
        synchronized (persistentCookieJar) {
            for (Cookie cookie : cookieCache) {
                // skip expired cookies; they are never sent and are dropped on the next request
                if (cookie.expiresAt() < now || !cookieMatchesDomain(cookie, domainFilter)) {
                    continue;
                }
                result.put(cookie.name(), cookieToJson(cookie));
            }
        }

        callbackContext.success(result);
    }

    // clearCookies(names, domainFilter)
    // args[0]: array of cookie names to remove, args[1] (optional): domain filter, as in getCookies.
    // Removes matching cookies from the plugin's cookie store. Returns the number of cookies removed.
    private void clearCookies(JSONArray args, CallbackContext callbackContext) throws JSONException {
        JSONArray namesArg = args.optJSONArray(0);
        if (namesArg == null || namesArg.length() == 0) {
            callbackContext.error("clearCookies: cookie names are required");
            return;
        }
        final Set<String> names = new HashSet<>();
        for (int i = 0; i < namesArg.length(); i++) {
            names.add(namesArg.getString(i));
        }
        final String domainFilter = domainFilterFromArgs(args, 1);

        int removed = removeCookies(new CookieFilter() {
            @Override
            public boolean matches(Cookie cookie) {
                return names.contains(cookie.name()) && cookieMatchesDomain(cookie, domainFilter);
            }
        });
        callbackContext.success(removed);
    }

    // clearAllCookies(domainFilter)
    // args[0] (optional): domain filter, as in getCookies. "all" (default) empties the plugin's cookie store.
    // Returns the number of cookies removed.
    private void clearAllCookies(JSONArray args, CallbackContext callbackContext) {
        final String domainFilter = domainFilterFromArgs(args, 0);

        int removed = removeCookies(new CookieFilter() {
            @Override
            public boolean matches(Cookie cookie) {
                return cookieMatchesDomain(cookie, domainFilter);
            }
        });
        callbackContext.success(removed);
    }

    private interface CookieFilter {
        boolean matches(Cookie cookie);
    }

    // Removes matching cookies from the in-memory cache and the persisted store; returns how many were removed
    private int removeCookies(CookieFilter filter) {
        // PersistentCookieJar's methods synchronize on the jar, so lock it while editing its cache and store
        synchronized (persistentCookieJar) {
            // keyed by cookie identity (name, domain, path, secure, hostOnly) so a cookie found in both
            // the cache and the persisted store is counted once
            Map<String, Cookie> removed = new LinkedHashMap<>();

            // the cache is what requests are sent from; session cookies only ever live here
            for (Iterator<Cookie> it = cookieCache.iterator(); it.hasNext();) {
                Cookie cookie = it.next();
                if (filter.matches(cookie)) {
                    it.remove();
                    removed.put(cookieIdentity(cookie), cookie);
                }
            }
            // also sweep the persisted store, which can hold stale copies the cache no longer has
            // (e.g. ones left on disk before SessionAwareCookieJar was added)
            for (Cookie cookie : cookiePersistor.loadAll()) {
                if (filter.matches(cookie)) {
                    removed.put(cookieIdentity(cookie), cookie);
                }
            }
            cookiePersistor.removeAll(removed.values());

            return removed.size();
        }
    }

    // "all" when the argument is missing, null or empty; otherwise the filter string
    private static String domainFilterFromArgs(JSONArray args, int index) {
        if (args.length() <= index || args.isNull(index)) {
            return "all";
        }
        String filter = args.optString(index, "all");
        return filter.isEmpty() ? "all" : filter;
    }

    private static boolean cookieMatchesDomain(Cookie cookie, String domainFilter) {
        return domainFilter.equals("all") || cookie.domain().contains(domainFilter);
    }

    private static JSONObject cookieToJson(Cookie cookie) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("name", cookie.name());
        json.put("value", cookie.value());
        json.put("domain", cookie.domain());
        json.put("path", cookie.path());
        json.put("expires", cookie.persistent() ? cookie.expiresAt() / 1000 : 0);
        json.put("secure", cookie.secure());
        json.put("httpOnly", cookie.httpOnly());
        json.put("version", 0); // OkHttp only models RFC 6265 cookies; iOS reports the same 0 for them
        return json;
    }

    private static String cookieIdentity(Cookie cookie) {
        return cookie.name() + "|" + cookie.domain() + "|" + cookie.path() + "|" + cookie.secure() + "|"
                + cookie.hostOnly();
    }

    //########### Set request max timeout
    private void setRequestTimeout(JSONArray args, CallbackContext callbackContext) throws JSONException {
        int connect = args.getInt(0);
        int write = args.getInt(1);
        int read = args.getInt(2);

        try {
            client = client.newBuilder()
                    .connectTimeout(connect, TimeUnit.SECONDS)
                    .writeTimeout(write, TimeUnit.SECONDS)
                    .readTimeout(read, TimeUnit.SECONDS)
                    .build();
            httpclient = httpclient.newBuilder()
                    .connectTimeout(connect, TimeUnit.SECONDS)
                    .writeTimeout(write, TimeUnit.SECONDS)
                    .readTimeout(read, TimeUnit.SECONDS)
                    .build();

            callbackContext.success("Request timeout set successfully!");
        } catch (Exception e) {
            Log.e("SSLSetRequestTimeoutError", e.getMessage());
            callbackContext.error(e.getMessage());
        }
    }

    // ########### Enable or disable SSL function
    private void enableSSLPinning(JSONArray args, CallbackContext callbackContext) throws JSONException {

        boolean sslstatus = args.getBoolean(0);
        // permanently enable the sslpinning as default: true

        try {
            if (!sslstatus) {
                client = client.newBuilder().certificatePinner(CertificatePinner.DEFAULT).build();
                SSL_PINNING_STATUS = false;
                SSL_PINNING_STOP = true;
                callbackContext.success("SSL Pinning disabled");
            } else {
                // client = client.newBuilder().certificatePinner(getPinnedHashes()).build();
                try {
                    doSSLpinning(args, callbackContext);
                } catch (Exception e) {
                    callbackContext.error(e.getMessage());
                }
                SSL_PINNING_STATUS = true;
                SSL_PINNING_STOP = false;
                callbackContext.success("SSL Pinning enabled");
            }

        } catch (Exception e) {
            Log.e("SSLflagError", e.getMessage());
            callbackContext.error(e.getMessage());
        }

    }

    // ########### Enable SSL pinning with Trust Manager, Helper function
    private void doSSLpinning(JSONArray args, final CallbackContext callbackContext) {

        Activity activity = this.cordova.getActivity();
        Context context = activity.getApplicationContext();
        CertificatePinner.Builder builder = new CertificatePinner.Builder();

        try {
            String[] fileNames = context.getAssets().list("certificates");
            for (String name : fileNames) {
                // Log.e("SSLpinning", "getPEM: " + name);
                if (name.endsWith(".pem")) {
                    String domainname = name.replaceAll(".pem$", "");
                    InputStream certInputStream = context.getAssets().open("certificates/" + name);
                    BufferedInputStream bis = new BufferedInputStream(certInputStream);
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Log.i("SSLpinning", "FOUND-PEM: " + name + " for domain: " + domainname);
                    while (bis.available() > 0) {
                        Certificate cert = certificateFactory.generateCertificate(bis);
                        builder.add(domainname, doGenerate256(domainname, cert));
                        domainlist.add(domainname);
                    }
                } else if (name.endsWith(".cer")) {
                    String domainname = name.replaceAll(".cer$", "");
                    InputStream certInputStream = context.getAssets().open("certificates/" + name);
                    BufferedInputStream bis = new BufferedInputStream(certInputStream);
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Log.i("SSLpinning", "FOUND-CER: " + name + " for domain: " + domainname);
                    while (bis.available() > 0) {
                        Certificate cert = certificateFactory.generateCertificate(bis);
                        builder.add(domainname, doGenerate256(domainname, cert));
                        domainlist.add(domainname);
                    }
                } else {
                    Log.i("SSLpinning", "getPEMdomain: not pem");
                }
            }

            client = client.newBuilder()
                    .certificatePinner(builder.build())
                    .build();
        } catch (Exception e) {
            Log.e("SSLpinning", "getsslconteXTException+" + e.getMessage());
        }

    }

    // #####################
    private String doGenerate256(String domainname, Certificate certificate) {

        if (!(certificate instanceof X509Certificate)) {
            throw new IllegalArgumentException("Certificate pinning requires X509 certificates");
        }
        String sha = "sha256/" + sha256((X509Certificate) certificate).base64();
        Log.i("SSLpinning", "SHAgenerated!! : " + sha + " for domain: " + domainname);
        return sha;
    }

    private ByteString sha256(X509Certificate x509Certificate) {
        return ByteString.of(x509Certificate.getPublicKey().getEncoded()).sha256();
    }

    // ########### get/post function, the 1st variable is "get" or "post"
    private void getpostMethod(String action, JSONArray args, final CallbackContext callbackContext)
            throws JSONException {

        // url : "https://www.google.co.in/search",
        // data : {q: "check+data", oq: "check+data"},
        // headers : {}, urlkey : "google"

        String url = args.getString(0);
        String urlkey;
        JSONObject qdata = new JSONObject();
        JSONObject headers = new JSONObject();
        String dest = "";
        boolean securedomain;
        boolean isjson = false;
        OkHttpClient useClient;

        final JSONObject retObj = new JSONObject();
        Headers.Builder headersBuilder = new Headers.Builder();
        final RequestBody formBody;

        Request request;

        if (!SSL_PINNING_STATUS && !SSL_PINNING_STOP) {
            try {
                doSSLpinning(args, callbackContext);
            } catch (Exception e) {
                callbackContext.error(e.getMessage());
            }

            SSL_PINNING_STATUS = true;
        }

        try {
            headersBuilder.set("User-Agent", settings.getUserAgentString()); // for user agent
        } catch (Exception e) {
            retObj.put("data", "");
            retObj.put("httperrorcode", 0);
            retObj.put("errorcode", -1);
            retObj.put("errorinfo", e.getMessage());
            callbackContext.error(retObj);
        }

        try {

            if (!action.equals("download"))
                qdata = args.getJSONObject(1);
            else
                dest = args.getString(1);

            headers = args.getJSONObject(2);

            try // lets iterate the headers object sent by the requesting function
            {

                Iterator<?> keys = headers.keys();
                while (keys.hasNext()) {
                    String key = (String) keys.next();
                    String value = headers.getString(key);
                    if (key.toLowerCase().contains("content-type") && value.toLowerCase().contains("json")) {
                        isjson = true;
                    }
                    headersBuilder.set(key, value);
                }
            } catch (Exception e) {
                // xx.toString();
                retObj.put("data", "");
                retObj.put("httperrorcode", 0);
                retObj.put("errorcode", -1);
                retObj.put("errorinfo", e.getMessage());
                callbackContext.error(retObj);
            }

        } catch (JSONException e) {
            Log.e("DataObjecterror", e.getMessage());
            retObj.put("data", "");
            retObj.put("httperrorcode", 0);
            retObj.put("errorcode", 0);
            retObj.put("errorinfo", e.getMessage());
            callbackContext.error(retObj);
        }

        if (url != null && url.length() > 0) {
            try {

                urlkey = args.getString(3);

                String domainname = Objects.requireNonNull(HttpUrl.parse(url)).host();
                String wildcarddomainname = Objects.requireNonNull(HttpUrl.parse(url)).host();

                String[] arr = domainname.split("\\.");
                if (arr.length == 2)// just a common case of wildcard domain supporting the root as well
                {
                    wildcarddomainname = "*." + arr[0] + '.' + arr[1];
                } else if (arr.length > 2) {
                    wildcarddomainname = "*";
                    for (int i = 1; i < arr.length; i++) {
                        wildcarddomainname += "." + arr[i];
                    }
                }
                Log.i("SSLpinning", "WILDCARDDomain: " + wildcarddomainname);

                if (domainlist.contains(domainname)) {
                    securedomain = true;
                    Log.i("SSLpinning", "ParsedDomain: " + domainname + " Type: Secure : " + urlkey);
                } else if (domainlist.contains(wildcarddomainname)) {
                    securedomain = true;
                    Log.i("SSLpinning", "ParsedWildCardDomain: " + domainname + " Type: Secure : " + urlkey);
                } else {
                    securedomain = false;
                    Log.i("SSLpinning", "ParsedDomain: " + domainname + " Type: Not Secure : " + urlkey);
                }
                // POST, PUT and DELETE
                if (action.equals("post") || action.equals("put") || action.equals("delete")) {
                    if (isjson) {
                        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
                        formBody = RequestBody.create(JSON, qdata.toString());
                    } else {
                        // ## adding the post parameters
                        FormBody.Builder formBuilder = new FormBody.Builder();
                        Iterator<?> keys = qdata.keys();
                        while (keys.hasNext()) {
                            String key = (String) keys.next();
                            formBuilder.add(key, qdata.getString(key));
                        }
                        formBody = formBuilder.build();
                        // ## post parameters done
                    }
                    Log.i("SSLpinning", "POSTasJSON: " + isjson);

                    newurl = url;

                    Request.Builder builder = new Request.Builder().url(newurl).headers(headersBuilder.build());

                    if (action.equals("put"))
                        request = builder.put(formBody).tag(urlkey).build();
                    else if (action.equals("delete"))
                        request = builder.delete(formBody).tag(urlkey).build();
                    else
                        request = builder.post(formBody).tag(urlkey).build();

                } else {

                    // ## adding the query parameters
                    HttpUrl.Builder httpBuider = Objects.requireNonNull(HttpUrl.parse(url)).newBuilder();
                    Iterator<?> keys = qdata.keys();
                    while (keys.hasNext()) {
                        String key = (String) keys.next();
                        httpBuider.addQueryParameter(key, qdata.getString(key));
                    }

                    newurl = httpBuider.build().toString();
                    request = new Request.Builder().url(newurl).headers(headersBuilder.build()).tag(urlkey).build();
                }

                if (securedomain) {
                    useClient = client;
                } else {
                    useClient = httpclient;
                }
                // for a download request add progress listener
                if (action.equals("download")) {
                    final ProgressListener progressListener = new ProgressListener() {
                        @Override
                        public void update(long bytesRead, long contentLength, boolean done) {
                            final JSONObject retObj = new JSONObject();
                            try {
                                if (!done) {
                                    if (contentLength != -1) {
                                        double progress = ((100 * (double) bytesRead) / (double) contentLength) / 100;

                                        retObj.put("progress", progress);
                                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, retObj);
                                        pluginResult.setKeepCallback(true);

                                        callbackContext.sendPluginResult(pluginResult);
                                    }
                                }
                            } catch (Exception e) {
                                String err = (e == null || e.getMessage() == null) ? "Donwload Progress Failed"
                                        : e.getMessage();
                                Log.e("SSLDWNError", err);
                            }
                        }
                    };
                    Log.i("SSLpinning", "create download client");
                    useClient = useClient.newBuilder()
                            .addNetworkInterceptor(new Interceptor() {
                                @NonNull
                                @Override
                                public Response intercept(@NonNull Chain chain) throws IOException {
                                    Response originalResponse = chain.proceed(chain.request());
                                    return originalResponse.newBuilder()
                                            .body(new ProgressResponseBody(originalResponse.body(), progressListener))
                                            .build();
                                }
                            }).build();
                }

                OkHttpUtils.cancelCallWithTag(useClient, urlkey);

                String finalDest = dest != null && dest.length() > 1 && !dest.equals("null") ? dest
                        : cordova.getContext().getFilesDir().toString() + "/"
                                + URLUtil.guessFileName(request.url().toString(), null, null);

                useClient.newCall(request).enqueue(new Callback() {
                    @Override
                    public void onFailure(@NonNull Call call, @NonNull IOException e) {
                        // e.printStackTrace();
                        try {
                            Log.e("SSLpINErroR", e.getMessage());
                            String errStr = e.getMessage();
                            String err = Objects.requireNonNull(errStr).toLowerCase();
                            JSONObject erritems = new JSONObject();

                            erritems.put("err-1202", "CertPathValidatorException");
                            erritems.put("err-1205", "Certificate pinning failure");
                            // erritems.put("err-1003", "No address associated with hostname");
                            erritems.put("err-1001", "failed to connect");
                            erritems.put("err-10", "No address associated with hostname"); // no internet
                            // erritems.put("err-10", "failed to connect"); //no internet
                            erritems.put("err-999", "Canceled"); // navigation cancelled by the app by triggering the
                                                                 // unique key method

                            retObj.put("data", "");
                            retObj.put("httperrorcode", 0);
                            retObj.put("errorcode", -1);

                            int myNum;

                            Iterator<String> iter = erritems.keys();
                            while (iter.hasNext()) {
                                String key = iter.next();
                                try {
                                    String val = erritems.get(key).toString();
                                    if (err.contains(val.toLowerCase())) {
                                        try {
                                            myNum = Integer.parseInt(key.replaceAll("err", ""));
                                            retObj.put("errorcode", myNum);
                                        } catch (NumberFormatException nfe) {
                                            System.out.println("Could not parse " + nfe);
                                        }
                                        // retObj.put("errorcode", key.replaceAll("err", ""));
                                        break;
                                    }
                                } catch (JSONException ee) {
                                    // Something went wrong!
                                }
                            }

                            retObj.put("errorinfo", errStr);
                        } catch (JSONException je) {
                            Log.e("Data object error", je.getMessage());
                        } catch (Exception fe) {
                            Log.e("onFailure SSL error", fe.getMessage());
                        }

                        callbackContext.error(retObj);
                        // callbackContext.error(e.getMessage());
                    }

                    @Override
                    public void onResponse(@NonNull Call call, @NonNull final Response response) {
                        try {

                            JSONObject jsonHeaders = new JSONObject();

                            Headers responseHeaders = response.headers();
                            for (int i = 0; i < responseHeaders.size(); i++) {
                                jsonHeaders.put(responseHeaders.name(i), responseHeaders.value(i));
                            }

                            retObj.put("headers", jsonHeaders);

                            if (response.isSuccessful()) {
                                if (action.equals("download")) {
                                    File file = new File(new URI(finalDest));
                                    file.createNewFile();
                                    BufferedSink sink = Okio.buffer(Okio.sink(file));
                                    // you can access body of response
                                    sink.writeAll(Objects.requireNonNull(response.body()).source());
                                    sink.close();

                                    Log.i("SSLpinning", "File downloaded to: " + finalDest);

                                    retObj.put("url", finalDest);

                                } else {
                                    retObj.put("data", Objects.requireNonNull(response.body()).string());
                                }

                                retObj.put("status", response.code());
                                callbackContext.success(retObj);

                            } else {
                                retObj.put("data", Objects.requireNonNull(response.body()).string());

                                retObj.put("httperrorcode", response.code());

                                if (response.code() >= 400 && response.code() <= 600) {
                                    retObj.put("errorcode", -1011);
                                } else {
                                    retObj.put("errorcode", response.code());
                                }

                                retObj.put("errorinfo", response.toString());

                                callbackContext.error(retObj);
                            }
                        } catch (JSONException e) {
                            Log.e("DataobjectError", e.getMessage());
                            callbackContext.error("DataObjectErrN" + e.getMessage());

                        } catch (Exception e) {
                            String err = (e == null || e.getMessage() == null) ? "Donwload Failed" : e.getMessage();
                            Log.e("SSLDWNGETPOSError", err);

                            try {
                                retObj.put("data", "");
                                retObj.put("httperrorcode", 0);
                                retObj.put("errorcode", 1203);
                                retObj.put("errorinfo", err);
                            } catch (JSONException ex) {
                            }

                            callbackContext.error(retObj);
                        }

                    }
                });

            } catch (Exception e) {
                // do something
                Log.e("SSLError", e.getMessage());
                retObj.put("data", "");
                retObj.put("httperrorcode", 0);
                retObj.put("errorcode", 1203);
                retObj.put("errorinfo", e.getMessage());
                callbackContext.error(retObj);
                // callbackContext.error(e.getMessage());
            }
        } else {
            retObj.put("data", "");
            retObj.put("httperrorcode", 0);
            retObj.put("errorcode", -1);
            retObj.put("errorinfo", "Incorrect url parameter");
            callbackContext.error(retObj);
            // callbackContext.error("Some problems with the url parameter");
        }
    }

    // ###############

}

// end of class method

// #############################