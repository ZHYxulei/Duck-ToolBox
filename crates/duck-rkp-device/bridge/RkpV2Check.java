package duck.rkp;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/** Checks empty-key V2 CSRs using the device's stable AIDL proxy. */
public final class RkpV2Check {
    private static final String PREFIX = "android.hardware.security.keymint.";
    private static final String SERVICE = PREFIX + "IRemotelyProvisionedComponent";
    private static final int CSR_LIMIT = 0xa000;
    private static final int TEXT_LIMIT = 1024;

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("expected exchange directory and instance");
        File directory = new File(args[0]);
        byte[] response;
        try {
            if (!args[1].matches("[A-Za-z0-9_.-]{1,64}")) {
                throw new IOException("invalid RKP instance");
            }
            response = request(directory, args[1]);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            if (failure.getClass().getName().equals("android.os.ServiceSpecificException")) {
                int code = failure.getClass().getField("errorCode").getInt(failure);
                response = errorReply(1, code, failure.toString());
            } else {
                response = errorReply(2, 0, failure.toString());
            }
        }
        try (FileOutputStream output = new FileOutputStream(new File(directory, "reply.bin"))) {
            output.write(response);
        }
    }

    private static byte[] request(File directory, String instance) throws Exception {
        byte[] challenge = new byte[32];
        try (DataInputStream input = new DataInputStream(
                new FileInputStream(new File(directory, "request.bin")))) {
            input.readFully(challenge);
            if (input.read() != -1) throw new IOException("challenge must be exactly 32 bytes");
        }
        Class<?> binder = Class.forName("android.os.IBinder");
        Object service = Class.forName("android.os.ServiceManager")
                .getMethod("checkService", String.class).invoke(null, SERVICE + "/" + instance);
        if (service == null) throw new IOException("RKP service is unavailable");
        Class<?> api = Class.forName(SERVICE);
        Object proxy = Class.forName(SERVICE + "$Stub")
                .getMethod("asInterface", binder).invoke(null, service);
        Object info = api.getMethod("getHardwareInfo").invoke(proxy);
        if (info == null) return errorReply(3, 0, "null hardware information");
        Class<?> hardware = info.getClass();
        int version = hardware.getField("versionNumber").getInt(info);
        int curve = hardware.getField("supportedEekCurve").getInt(info);
        if (version < 3) {
            return errorReply(4, 0, "V2 requires hardware version >= 3; versionNumber=" + version);
        }
        Method interfaceMethod = null;
        try {
            interfaceMethod = api.getMethod("getInterfaceVersion");
        } catch (NoSuchMethodException ignored) {
            // Older AIDL Java bindings omit this optional metadata method.
        }
        int interfaceVersion = interfaceMethod == null ? -1 : (Integer) interfaceMethod.invoke(proxy);
        String author = (String) hardware.getField("rpcAuthorName").get(info);
        String uniqueId = (String) hardware.getField("uniqueId").get(info);
        if (author == null || uniqueId == null) return errorReply(3, 0, "null hardware text field");
        byte[] authorBytes = author.getBytes(StandardCharsets.UTF_8);
        byte[] uniqueBytes = uniqueId.getBytes(StandardCharsets.UTF_8);
        if (authorBytes.length > TEXT_LIMIT || uniqueBytes.length > TEXT_LIMIT) {
            return errorReply(3, 0, "hardware text field exceeds 1024 UTF-8 bytes");
        }
        Object keys = Array.newInstance(Class.forName(PREFIX + "MacedPublicKey"), 0);
        Method generate = api.getMethod("generateCertificateRequestV2", keys.getClass(), byte[].class);
        byte[] empty = (byte[]) generate.invoke(proxy, keys, new byte[0]);
        if (!validCsr(empty)) return errorReply(3, 0, "invalid empty-challenge CSR length");
        byte[] challenged = (byte[]) generate.invoke(proxy, keys, challenge);
        if (!validCsr(challenged)) return errorReply(3, 0, "invalid challenged CSR length");
        // No CSR is serialized until both independent calls and all validation succeed.
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(0);
            output.writeInt(version);
            output.writeInt(curve);
            output.writeInt(interfaceVersion);
            writeField(output, authorBytes);
            writeField(output, uniqueBytes);
            writeField(output, empty);
            writeField(output, challenged);
        }
        return buffer.toByteArray();
    }

    private static boolean validCsr(byte[] csr) {
        return csr != null && csr.length > 0 && csr.length <= CSR_LIMIT;
    }

    private static byte[] errorReply(int status, int code, String message) throws IOException {
        int end = 0;
        int length = 0;
        while (end < message.length()) {
            int point = message.codePointAt(end);
            int bytes = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
            if (length + bytes > TEXT_LIMIT) break;
            length += bytes;
            end += Character.charCount(point);
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(status);
            if (status == 1) output.writeInt(code);
            writeField(output, message.substring(0, end).getBytes(StandardCharsets.UTF_8));
        }
        return buffer.toByteArray();
    }

    private static void writeField(DataOutputStream output, byte[] bytes) throws IOException {
        output.writeInt(bytes.length);
        output.write(bytes);
    }
}
