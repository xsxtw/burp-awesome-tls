package burp;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;

public interface ServerLibrary extends Library {
    ServerLibrary INSTANCE = Native.load("server.h", ServerLibrary.class);
//    ServerLibrary INSTANCE = Native.load((Platform.isMac() ? "lib" : "") +  "server." + (Platform.isWindows() ? "dll" : Platform.isMac() ? "dylib" : "so"), ServerLibrary.class);

    String StartServer(String interceptAddr, String burpAddr, String spoofAddr);
    String StopServer();
    void SmokeTest();
}
