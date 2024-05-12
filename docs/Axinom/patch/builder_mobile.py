from pathlib import Path

import yaml

# @Info: values to be patch
PATCH = {
    "assets/samplelist.json": [
      [None, "samplelist.json"]
    ],
    "com/axinom/drm/sample/activity/SampleChooserActivity.smali": [
        ["SampleChooserActivity.smali", None]
    ]
}

# @Info: Keystore to sign the application
KEYSTORE = {
    "algo": "RSA",
    "size": 2048,
    "sign": "SHA-256",
    "validity": 365 * 25,
    "password": "Axinom_PASSWORD",
    "alias": "Axinom_DRM_DEMO",
    "meta": {
        "common_name": "Axinom",
        "organizational_unit": "Front-End",
        "organization": "Axinom",
        "locality": "Tartu",
        "state": "Tartumaa",
        "country": "EE",
    }
}

# @Info: Info about application
METADATA = {
    # "name": "Axinom DRM Sample Player",
    "version": "202211021",
    "source": "https://github.com/Axinom/drm-sample-player-android",
    "input": "axinom.apk",
    "output": "axinom_signed.apk",
}

if __name__ == "__main__":
    Path("config.yaml").write_text(yaml.dump({
        "metadata": METADATA,
        "keystore": KEYSTORE,
        "patch": PATCH
    }))
