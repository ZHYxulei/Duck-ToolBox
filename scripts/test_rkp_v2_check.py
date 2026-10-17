"""Compile the real Java V2 checker against fake AIDL; no device, root or network."""
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "crates/duck-rkp-device/bridge/RkpV2Check.java"
JAVA = shutil.which("java.exe") or shutil.which("java")
JAVAC = shutil.which("javac.exe") or shutil.which("javac")
CHALLENGE = bytes(range(32))
STUBS = {
    "android/os/IBinder.java": "package android.os; public interface IBinder {}",
    "android/os/ServiceSpecificException.java": """
package android.os;
public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;
    public ServiceSpecificException(int code, String message) { super(message); errorCode = code; }
}
""",
    "android/os/ServiceManager.java": """
package android.os;
public class ServiceManager {
    public static IBinder checkService(String name) throws Exception {
        if (!name.equals("android.hardware.security.keymint.IRemotelyProvisionedComponent/"
                + System.getProperty("test.instance", "default")))
            throw new AssertionError("wrong service instance");
        java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("test.log")),
                new byte[] {0}, java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND);
        return Boolean.getBoolean("test.missing") ? null : new IBinder() {};
    }
}
""",
    "android/hardware/security/keymint/RpcHardwareInfo.java": """
package android.hardware.security.keymint;
public class RpcHardwareInfo {
    public int versionNumber = Integer.getInteger("test.version", 3);
    public int supportedEekCurve = Integer.getInteger("test.curve", 0);
    public String rpcAuthorName = text("test.author", "作者");
    public String uniqueId = text("test.unique", "unique-设备");
    private static String text(String property, String fallback) {
        String mode = System.getProperty(property, "");
        if (mode.equals("null")) return null;
        if (mode.equals("empty")) return "";
        if (mode.equals("limit")) return new String(new char[512]).replace("\\0", "é");
        if (mode.equals("large")) return new String(new char[513]).replace("\\0", "é");
        return fallback;
    }
}
""",
    "android/hardware/security/keymint/MacedPublicKey.java": """
package android.hardware.security.keymint;
public class MacedPublicKey {
    public MacedPublicKey() { throw new AssertionError("must not construct any key"); }
}
""",
    "android/hardware/security/keymint/IRemotelyProvisionedComponent.java": """
package android.hardware.security.keymint;
public interface IRemotelyProvisionedComponent {
    RpcHardwareInfo getHardwareInfo();
    int getInterfaceVersion();
    byte[] generateCertificateRequestV2(MacedPublicKey[] keys, byte[] challenge) throws Exception;
    public static class Stub {
        public static IRemotelyProvisionedComponent asInterface(android.os.IBinder binder) {
            if (binder == null) throw new AssertionError("null binder");
            return new Proxy();
        }
        private static class Proxy implements IRemotelyProvisionedComponent {
            private int calls;
            private void fail(String stage) throws RuntimeException {
                if (!System.getProperty("test.fail", "").equals(stage)) return;
                String message = Boolean.getBoolean("test.longMessage")
                        ? new String(new char[900]).replace("\\0", "猫🙂") : "HAL rejected request";
                RuntimeException failure = Boolean.getBoolean("test.transport")
                        ? new IllegalStateException(message)
                        : new android.os.ServiceSpecificException(Integer.getInteger("test.code", -40), message);
                throw failure;
            }
            public RpcHardwareInfo getHardwareInfo() {
                fail("hardware");
                return Boolean.getBoolean("test.nullHardware") ? null : new RpcHardwareInfo();
            }
            public int getInterfaceVersion() {
                fail("interface");
                return 5;
            }
            public byte[] generateCertificateRequestV2(MacedPublicKey[] keys, byte[] challenge)
                    throws Exception {
                calls++;
                java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("test.log")),
                        new byte[] {(byte) calls}, java.nio.file.StandardOpenOption.APPEND);
                if (keys == null || keys.length != 0) throw new AssertionError("nonempty keys");
                if (calls == 1 && challenge.length != 0) throw new AssertionError("not empty challenge");
                if (calls == 2) {
                    if (challenge.length != 32) throw new AssertionError("wrong challenge length");
                    for (int i = 0; i < 32; i++)
                        if (challenge[i] != i) throw new AssertionError("challenge changed");
                }
                if (calls > 2) throw new AssertionError("extra CSR call");
                fail("call" + calls);
                String mode = System.getProperty("test.csr" + calls, "valid");
                if (mode.equals("null")) return null;
                if (mode.equals("empty")) return new byte[0];
                if (mode.equals("large")) return new byte[0xa001];
                if (mode.equals("limit")) return new byte[0xa000];
                return calls == 1 ? new byte[] {11, 12} : new byte[] {21, 22, 23};
            }
        }
    }
}
""",
}


def frame(value):
    return struct.pack(">i", len(value)) + value


class BridgeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not JAVA or not JAVAC:
            raise RuntimeError("Java JDK (java and javac) is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="rkp-v2-check-")
        cls.root = pathlib.Path(cls.temporary.name)
        cls.classes = cls.compile_fixture(cls.root / "normal", STUBS)
        no_version = dict(STUBS)
        api = "android/hardware/security/keymint/IRemotelyProvisionedComponent.java"
        no_version[api] = no_version[api].replace("    int getInterfaceVersion();\n", "")
        cls.no_version = cls.compile_fixture(cls.root / "no-version", no_version)
        no_v2 = dict(STUBS)
        no_v2[api] = no_v2[api].replace(
            "    byte[] generateCertificateRequestV2(MacedPublicKey[] keys, byte[] challenge) throws Exception;\n", "")
        cls.no_v2 = cls.compile_fixture(cls.root / "no-v2", no_v2)

    @classmethod
    def compile_fixture(cls, root, stubs):
        classes = root / "classes"
        classes.mkdir(parents=True)
        sources = [str(BRIDGE)]
        for relative, source in stubs.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            sources.append(str(path))
        subprocess.run([JAVAC, "--release", "8", "-encoding", "UTF-8", "-d", str(classes), *sources],
                       check=True, timeout=30)
        return classes

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_bridge(self, properties=None, request=CHALLENGE, instance="default", classes=None):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            exchange = pathlib.Path(directory)
            if request is not None:
                (exchange / "request.bin").write_bytes(request)
            log = exchange / "calls.bin"
            flags = [f"-Dtest.log={log}"]
            flags.extend(f"-Dtest.{key}={value}" for key, value in (properties or {}).items())
            result = subprocess.run([JAVA, *flags, "-cp", str(classes or self.classes),
                                     "duck.rkp.RkpV2Check", directory, instance],
                                    check=True, timeout=10, capture_output=True)
            self.assertEqual(result.stdout, b"", "must never print a CSR")
            self.assertEqual(result.stderr, b"")
            return (exchange / "reply.bin").read_bytes(), log.read_bytes() if log.exists() else b""

    def assert_error(self, response, status, code=None):
        self.assertEqual(struct.unpack_from(">i", response)[0], status)
        offset = 4
        if status == 1:
            self.assertEqual(struct.unpack_from(">i", response, offset)[0], code)
            offset += 4
        length = struct.unpack_from(">i", response, offset)[0]
        self.assertGreaterEqual(length, 0)
        self.assertLessEqual(length, 1024)
        self.assertEqual(len(response), offset + 4 + length, "no partial success or CSR fields")
        return response[offset + 4:].decode("utf-8", errors="strict")

    def test_two_calls_empty_keys_exact_challenges_and_success_protocol(self):
        for instance in ["default", "strongbox", "a_A-0.b", "a" * 64]:
            with self.subTest(instance=instance):
                response, calls = self.run_bridge({"instance": instance}, instance=instance)
                self.assertEqual(calls, b"\0\1\2")
                self.assertEqual(response, struct.pack(">iiii", 0, 3, 0, 5)
                                 + frame("作者".encode()) + frame("unique-设备".encode())
                                 + frame(bytes([11, 12])) + frame(bytes([21, 22, 23])))

    def test_legacy_hardware_is_unsupported_without_v2_calls(self):
        for version in [-1, 0, 1, 2]:
            response, calls = self.run_bridge({"version": version, "fail": "call1"})
            self.assertIn(f"versionNumber={version}", self.assert_error(response, 4))
            self.assertEqual(calls, b"\0")

    def test_only_missing_interface_method_becomes_minus_one(self):
        response, calls = self.run_bridge(classes=self.no_version)
        self.assertEqual(struct.unpack_from(">iiii", response), (0, 3, 0, -1))
        self.assertEqual(calls, b"\0\1\2")
        for transport in ["true", "false"]:
            response, calls = self.run_bridge({"fail": "interface", "transport": transport})
            self.assert_error(response, 2 if transport == "true" else 1, -40)
            self.assertEqual(calls, b"\0")

    def test_missing_v2_method_is_not_silently_accepted(self):
        response, calls = self.run_bridge(classes=self.no_v2)
        self.assertIn("NoSuchMethodException", self.assert_error(response, 2))
        self.assertEqual(calls, b"\0")

    def test_aidl_codes_and_transport_errors_at_each_call(self):
        for stage, expected_calls in [("hardware", b"\0"), ("interface", b"\0"),
                                      ("call1", b"\0\1"), ("call2", b"\0\1\2")]:
            for code in [0, 2, -40]:
                with self.subTest(stage=stage, code=code):
                    response, calls = self.run_bridge({"fail": stage, "code": code})
                    self.assertIn("HAL rejected request", self.assert_error(response, 1, code))
                    self.assertEqual(calls, expected_calls)
            response, calls = self.run_bridge({"fail": stage, "transport": "true"})
            self.assert_error(response, 2)
            self.assertEqual(calls, expected_calls)
        response, _ = self.run_bridge({"missing": "true"})
        self.assert_error(response, 2)

    def test_invalid_csr_results_are_independent_and_never_return_partial_csr(self):
        for call in [1, 2]:
            for mode in ["null", "empty", "large"]:
                with self.subTest(call=call, mode=mode):
                    response, calls = self.run_bridge({f"csr{call}": mode})
                    self.assert_error(response, 3)
                    self.assertEqual(calls, b"\0\1" if call == 1 else b"\0\1\2")
        response, calls = self.run_bridge({"csr1": "limit", "csr2": "limit"})
        self.assertEqual(struct.unpack_from(">i", response)[0], 0)
        self.assertEqual(len(response), 16 + 4 + len("作者".encode())
                         + 4 + len("unique-设备".encode()) + 8 + 2 * 0xa000)
        self.assertEqual(calls, b"\0\1\2")

    def test_utf8_text_limits_are_bytes_and_null_hardware_is_invalid(self):
        for field in ["author", "unique"]:
            for mode in ["null", "large"]:
                response, calls = self.run_bridge({field: mode})
                self.assert_error(response, 3)
                self.assertEqual(calls, b"\0")
            for mode in ["empty", "limit"]:
                response, _ = self.run_bridge({field: mode})
                self.assertEqual(struct.unpack_from(">i", response)[0], 0)
        response, _ = self.run_bridge({"nullHardware": "true"})
        self.assert_error(response, 3)

    def test_utf8_error_message_truncation_preserves_valid_encoding(self):
        for transport in ["true", "false"]:
            response, _ = self.run_bridge({"fail": "call2", "longMessage": "true", "transport": transport})
            message = self.assert_error(response, 2 if transport == "true" else 1, -40)
            self.assertIn("猫🙂", message)
            self.assertGreater(len(message.encode()), 1000)

    def test_malformed_request_is_rejected_before_service_lookup(self):
        for request in [None, b"", bytes(31), bytes(33), bytes(4096), frame(CHALLENGE)]:
            with self.subTest(length=None if request is None else len(request)):
                response, calls = self.run_bridge(request=request)
                self.assert_error(response, 2)
                self.assertEqual(calls, b"")

    def test_invalid_instance_is_rejected_before_service_lookup(self):
        for instance in ["", "a" * 65, "../default", "default/other", "with space", "设备", "a\n"]:
            with self.subTest(instance=instance):
                response, calls = self.run_bridge(instance=instance)
                self.assert_error(response, 2)
                self.assertEqual(calls, b"")

    def test_bridge_compiles_to_one_top_level_class(self):
        self.assertEqual([path.name for path in (self.classes / "duck/rkp").glob("*.class")],
                         ["RkpV2Check.class"])


if __name__ == "__main__":
    unittest.main()
