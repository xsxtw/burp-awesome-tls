package burp;


/**
 * Represents the configuration for a transport.
 */
public class TransportConfig {
    /*
    * Hostname.
     */
    public String Host;

    /**
     * Protocol scheme (HTTP or HTTPS).
     */
    public String Scheme;

    /**
     * The TLS fingerprint to use.
     */
    public String Fingerprint;

    /*
     * Hexadecimal Client Hello
     */
    public String HexClientHello;

    /**
     * The maximum amount of time a dial will wait for a connect to complete.
     * Defaults to 30 seconds.
     */
    public int HttpTimeout;

    /**
     * Specifies the interval between keep-alive probes for an active network connection.
     * Defaults to 30 seconds.
     */
    public int HttpKeepAliveInterval;

    /**
     * The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.
     * Defaults to 90 seconds.
     */
    public int IdleConnTimeout;
}

