import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import xmltodict
import yaml


def any2str(data: any) -> str:
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8")

    if isinstance(data, (dict, list)):
        data = json.dumps(data, indent=2, separators=(",", ":"))

    return str(data)


class Keystore:

    def __init__(
            self,
            algo: str = "RSA",
            size: int = 2048,
            sign: str = "SHA-256",
            validity: int = 365,
            password: str = None,
            alias: str = None,
            meta: dict = None,
            path: Path = Path("..")
    ):
        assert path.is_dir(), "Invalid Dir Path"
        assert algo in ["RSA", "EC", "DSA"], "Invalid Algorithm"
        assert sign in ["MD5", "SHA-1", "SHA-256", "SHA-512"], "Invalid Signature"

        if algo == "RSA":
            assert size in [1024, 2048, 3072, 4096], "Invalid RSA Size"
            assert sign in ["MD5", "SHA-1", "SHA-256", "SHA-512"], "Invalid RSA Signature"
        elif algo == "EC":
            assert size in [192, 224, 256, 384, 521], "Invalid EC Size"
            assert sign in ["SHA-256", "SHA-512"], "Invalid EC Signature"
        elif algo == "DSA":
            assert size in [1024], "Invalid DSA Size"
            assert sign in ["SHA-1"], "Invalid DSA Signature"

        self.algorithm = algo
        self.size = size
        self.signature = "{}with{}".format(
            sign.replace("-", ""),
            "ECDSA" if algo == "EC" else algo
        )
        self.digest = sign
        self.validity = validity
        meta = meta if meta else {}
        self.metadata = {
            "common_name": meta.get("common_name", "Unknown"),
            "organizational_unit": meta.get("organizational_unit", "Unknown"),
            "organization": meta.get("organization", "Unknown"),
            "locality": meta.get("locality", "Unknown"),
            "state": meta.get("state", "Unknown"),
            "country": meta.get("country", "Unknown"),
        }

        match = re.search(r'[\s:]?([a-zA-Z]+)', self.metadata["common_name"])
        name = re.sub(r'[^A-Za-z0-9]', "", match.group(1)).lower() if match else "keystore"
        self.path = path / f"{name}_{algo.lower()}.p12"
        self.password = password or f"{name}_password"
        self.alias = alias or f"{name}_alias"

    def __repr__(self) -> str:
        return json.dumps({
            "path": str(self.path),
            "algorithm": self.algorithm,
            "size": self.size,
            "signature": self.signature,
            "digest": self.digest,
            "validity": self.validity,
            "password": self.password,
            "alias": self.alias,
            "metadata": self.metadata
        }, indent=2)

    def sign(self, path: Path) -> None:
        assert path.is_file() and path.suffix == ".apk", "Invalid APK Path"

        if not self.path.is_file():
            tmp = Path("keystore.jks")
            os.system(
                'keytool -genkeypair -keystore "{}" -alias "{}" -keyalg "{}" -keysize "{}" -sigalg "{}" -validity "{}" -storepass "{}" -keypass "{}" -dname "CN=\\"{}\\", OU=\\"{}\\", O=\\"{}\\", L=\\"{}\\", ST=\\"{}\\", C=\\"{}\\"" -noprompt'.format(
                    tmp, self.alias, self.algorithm, self.size, self.signature,
                    self.validity, self.password, self.password, self.metadata["common_name"],
                    self.metadata["organizational_unit"], self.metadata["organization"],
                    self.metadata["locality"], self.metadata["state"], self.metadata["country"]
                ))

            os.system(
                'keytool -importkeystore -srckeystore "{}" -srcstorepass "{}" -destkeystore "{}" -deststoretype "PKCS12" -deststorepass "{}" -destkeypass "{}" -srcalias "{}"'.format(
                    tmp, self.password, self.path, self.password, self.password, self.alias
                ))
            tmp.unlink(missing_ok=True)
        os.system('apksigner sign --ks "{}" --ks-key-alias "{}" --ks-pass "pass:{}" --key-pass "pass:{}" "{}"'.format(
            self.path, self.alias, self.password, self.password, path
        ))
        Path(str(path) + ".idsig").unlink(missing_ok=True)

    def info(self, path: Path) -> None:
        assert path.is_file() and path.suffix == ".apk", "Invalid APK Path"
        os.system(f'apksigner verify --print-certs "{path}"')


class ApkTool:

    def __init__(self, instance: Path = Path(".apktool")):
        self.instance = instance

    def decompile(self, path: Path) -> None:
        assert path.is_file() and path.suffix == ".apk", "Invalid APK Path"
        if not self.instance.is_dir():
            os.system(f'apktool d "{path}" -o "{self.instance}" -f --no-crunch --only-main-classes')

    def compile(self, path: Path) -> None:
        assert path.suffix == ".apk", "Invalid APK Path"
        if not path.is_file():
            assert self.instance.is_dir(), "Invalid ApkTool Path"
            tmp = Path("unaligned.apk")

            os.system(f'apktool b "{self.instance}" -o "{tmp}" -f --no-crunch')
            if tmp.is_file(): os.system(f'zipalign -f -p "4" "{tmp}" "{path}"')
            if path.is_file(): shutil.rmtree(self.instance, ignore_errors=True)
            tmp.unlink(missing_ok=True)


def rename_app(parent: Path, name: str) -> None:
    manifest_path = parent / "AndroidManifest.xml"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)

    manifest_dict = xmltodict.parse(manifest_path.read_bytes(), encoding="utf-8")
    value = str(manifest_dict["manifest"]["application"]["@android:label"])
    if value.startswith("@string/"):
        key = value.split("@string/")[1]

        source = None
        for path in (parent / "res").iterdir():
            strings_path = path / "strings.xml"
            if "values" in str(path) and strings_path.is_file():
                strings_dict = xmltodict.parse(strings_path.read_bytes(), encoding="utf-8")

                for item in strings_dict["resources"]["string"]:
                    if isinstance(item, dict) and item["@name"] == key:
                        source = item["#text"]
                        print(f"I: Patching {strings_path.name} ({strings_path.parent})")
                        if source != name:
                            item["#text"] = name
                            strings_path.write_bytes(
                                xmltodict.unparse(strings_dict, encoding="utf-8", pretty=True).encode("utf-8"))
                        break
        if not source:
            raise ImportError(value)
    else:
        manifest_dict["manifest"]["application"]["@android:label"] = name
        manifest_path.write_bytes(xmltodict.unparse(manifest_dict, encoding="utf-8", pretty=True).encode("utf-8"))
        print(f"I: Patching {manifest_path.name} ({manifest_path.parent})")


if __name__ == "__main__":
    config = Path("config.yaml")
    if not config.is_file():
        config = Path(input("Config Path: "))
    if not config.is_file():
        raise FileNotFoundError(config)

    content = yaml.safe_load(config.read_text())

    apktool = ApkTool()
    jks = Keystore(**content["keystore"])
    src = Path(content["metadata"]["input"])
    opt = Path(content["metadata"]["output"])

    for key, value in content["metadata"].items():
        print(f"I: {key.capitalize()}: {value}")

    if not opt.is_file():
        apktool.decompile(src)

        # @Info: Patch apk
        for key, value in content["patch"].items():  # {Path: list[tuple]}

            path = apktool.instance / key
            if not path.is_file():
                exist = False
                for subp in apktool.instance.iterdir():
                    path = subp / key
                    if path.is_file():
                        exist = True
                        break

                if not exist:
                    raise FileNotFoundError(key)

            src_data = path.read_text()
            for v in value:
                if v[0] is None:
                    if isinstance(v[1], str):
                        # @Info: Replace complet file using [None, Path]
                        v[1] = Path(v[1])
                        if not v[1].is_file():
                            raise FileNotFoundError(v[1])
                        src_data = v[1].read_text()
                    elif v[1] is None:
                        # @Info: Replace with empty file
                        src_data = ""
                    else:
                        # @Info: Replace with custom char
                        src_data = any2str(v[1])
                elif v[1] is None:
                    # @Info: Replace functon using [Path, None]
                    if not isinstance(v[0], str):
                        raise ImportError(v[0])

                    v[0] = Path(v[0])
                    if not v[0].is_file():
                        raise FileNotFoundError(v[0])

                    opt_data = v[0].read_text()
                    if opt_data not in src_data:
                        try:
                            keys = opt_data.split("\n")
                            start = next(filter(None, keys), None)
                            stop = next(filter(None, reversed(keys)), None)
                            start_index = src_data.index(start)
                            stop_index = src_data.index(stop, start_index) + len(stop)
                            src_data = src_data.replace(src_data[start_index:stop_index], opt_data)
                        except Exception as e:
                            raise ValueError(v[0])
                else:
                    # @Info: Replace char using [str, str]
                    if not v[0] in src_data and not v[1] in src_data:
                        raise ImportError(v[0])
                    src_data = src_data.replace(*v)

            path.write_text(src_data)
            print(f"I: Patching {path.name} ({path.parent})")

        # @Info: Rename apk
        name = content["metadata"].get("name")
        if name:
            rename_app(apktool.instance, name)

        apktool.compile(opt)
        print(f"I: Keystore: {jks.path}")
        print(f"I: Validity: {jks.validity}")
        jks.sign(opt)

    jks.info(opt)

    print(f'I: MD5: {hashlib.md5(opt.read_bytes()).hexdigest()}')
