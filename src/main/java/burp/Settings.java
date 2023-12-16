package burp;

public class Settings {
    private final IBurpExtenderCallbacks callbacks;

    private final String address = "Address";
    private final String fingerprint = "Fingerprint";
    private final String hexClientHello = "HexClientHello";
    private final String httpTimeout = "HttpTimeout";
    private final String httpKeepAliveInterval = "HttpKeepAliveInterval";
    private final String idleConnTimeout = "IdleConnTimeout";

    public static final String DEFAULT_ADDRESS = "127.0.0.1:8887";
    public static final String DEFAULT_HTTP_TIMEOUT = "30";
    public static final String DEFAULT_IDLE_CONN_TIMEOUT = "90";
    public static final String DEFAULT_TLS_HANDSHAKE_TIMEOUT = "10";
    public static final String DEFAULT_TLS_FINGERPRINT = "Default";

    public Settings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.setDefaults();
    }

    private void setDefaults() {
        if (this.read(this.address) == null) {
            this.write(this.address, DEFAULT_ADDRESS);
        }

        if (this.read(this.fingerprint) == null) {
            this.write(this.fingerprint, DEFAULT_TLS_FINGERPRINT);
        }

        if (this.read(this.httpTimeout) == null) {
            this.write(this.httpTimeout, DEFAULT_HTTP_TIMEOUT);
        }

        if (this.read(this.httpKeepAliveInterval) == null) {
            this.write(this.httpKeepAliveInterval, DEFAULT_HTTP_TIMEOUT);
        }

        if (this.read(this.idleConnTimeout) == null) {
            this.write(this.idleConnTimeout, DEFAULT_IDLE_CONN_TIMEOUT);
        }
    }

    public String read(String key) {
       return this.callbacks.loadExtensionSetting(key);
    }

    public void write(String key, String value) {
        this.callbacks.saveExtensionSetting(key, value);
    }

    public String getAddress() {
        return this.read(this.address);
    }

    public void setAddress(String address) {
        this.write(this.address, address);
    }

    public int getHttpTimeout() {
        return Integer.parseInt(this.read(this.httpTimeout));
    }

    public void setHttpTimeout(int httpTimeout) {
        this.write(this.httpTimeout, String.valueOf(httpTimeout));
    }

    public int getHttpKeepAliveInterval() {
        return Integer.parseInt(this.read(this.httpKeepAliveInterval));
    }

    public void setHttpKeepAliveInterval(int httpTimeout) {
        this.write(this.httpKeepAliveInterval, String.valueOf(httpTimeout));
    }

    public String getFingerprint() { return this.read(this.fingerprint); }

    public void setFingerprint(String fingerprint) {
        this.write(this.fingerprint, fingerprint);
    }

    public String getHexClientHello() { return this.read(this.hexClientHello); }

    public void setHexClientHello(String hexClientHello) { this.write(this.hexClientHello, hexClientHello); }

    public int getIdleConnTimeout() {
        return Integer.parseInt(this.read(this.idleConnTimeout));
    }

    public void setIdleConnTimeout(int idleConnTimeout) {
        this.write(this.idleConnTimeout, String.valueOf(idleConnTimeout));
    }

    public String[] getFingerprints() {
        return new String[]{
                "Default",
                "Chrome 120",
                "Chrome 117",
                "Chrome 116 PSK PQ",
                "Chrome 116 PSK",
                "Chrome 112",
                "Chrome 111",
                "Chrome 110",
                "Chrome 109",
                "Chrome 108",
                "Chrome 107",
                "Chrome 106",
                "Chrome 105",
                "Chrome 104",
                "Chrome 103",

                "Firefox 117",
                "Firefox 110",
                "Firefox 108",
                "Firefox 106",
                "Firefox 105",
                "Firefox 104",
                "Firefox 102",

                "Opera 91",
                "Opera 90",
                "Opera 89",

                "Safari 16.0",
                "Safari 15.6.1",

                "Safari ipad 15.6",

                "Safari ios 16.0",
                "Safari ios 15.6",
                "Safari ios 15.5",

                "OkHttp4 android 13",
                "OkHttp4 android 12",
                "OkHttp4 android 11",
                "OkHttp4 android 10",
                "OkHttp4 android 9",
                "OkHttp4 android 8",
                "OkHttp4 android 7",
        };
    }
}
