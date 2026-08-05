#!/usr/bin/env python3
"""Monthly irext sync: import NEW remotes from the irext database as
encrypted packs and append them to the manifest.

Only pack ids not already in the manifest are added — existing packs are
never rewritten (encryption nonces would churn the whole repo otherwise).

Env:
  IRPACK_KEY1   hex of the 16-byte static key part (required)
  IREXT_DB      path to irext sqlite db
  IREXT_BINS    path to extracted binaries dir
  IREXT_DUMP    path to compiled irext_dump binary
"""

import hashlib, hmac as hmac_mod, json, os, re, sqlite3, subprocess, sys
from collections import defaultdict
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.environ["IREXT_DB"]
BINDIR = os.environ["IREXT_BINS"]
DUMP = os.environ["IREXT_DUMP"]
TMP = "/tmp/irext-decode.json"

KEY_PART_1 = bytes.fromhex(os.environ["IRPACK_KEY1"])
SALT2 = bytes([0x5B, 0xC8, 0x31, 0x9E, 0xA4, 0xD7, 0x66, 0x0F])
MAGIC = b"IRv2"

CATEGORY = {
    1: "airConditioner", 2: "tv", 3: "setTopBox", 4: "streamingBox",
    5: "setTopBox", 6: "mediaPlayer", 7: "fan", 8: "projector",
    9: "audioReceiver", 10: "light", 11: "setTopBox", 12: "robotVacuum",
    13: "airPurifier", 14: "airPurifier",
}
STD = {0: "power", 1: "mute", 2: "up", 3: "down", 4: "left", 5: "right",
       6: "ok", 7: "volumeUp", 8: "volumeDown", 9: "back", 10: "input",
       11: "menu"}
DIGITS = {14 + i: f"digit{i}" for i in range(10)}
KEYMAP = {
    2: {**STD, 12: "home", 13: "settings", **DIGITS},
    3: {**STD, 12: "channelUp", 13: "channelDown", **DIGITS},
    5: {**STD, 12: "channelUp", 13: "channelDown", **DIGITS},
    11: {**STD, 12: "channelUp", 13: "channelDown", **DIGITS},
    4: {0: "power", 1: "up", 2: "down", 3: "left", 4: "right", 5: "ok",
        6: "volumeUp", 7: "volumeDown", 8: "back", 9: "menu", 10: "home"},
    6: {0: "power", 1: "up", 2: "down", 3: "left", 4: "right", 5: "ok",
        6: "volumeUp", 7: "volumeDown", 8: "play", 9: "pause", 10: "eject",
        11: "rewind", 12: "fastForward", 13: "menu"},
    7: {0: "power", 6: "fanSpeedUp", 7: "fanSpeedDown", 8: "fanOscillate",
        9: "fanMode", 10: "fanTimer"},
    8: {0: "power", 1: "up", 2: "down", 3: "left", 4: "right", 5: "ok",
        6: "volumeUp", 7: "volumeDown", 8: "zoomOut", 9: "menu",
        10: "zoomIn", 11: "back"},
    9: {0: "power", 1: "up", 2: "down", 3: "left", 4: "right", 5: "ok",
        6: "volumeUp", 7: "volumeDown", 8: "mute", 9: "menu"},
    10: {0: "power", 1: "green", 2: "yellow", 3: "blue", 5: "red",
         6: "brightnessUp", 7: "brightnessDown", 8: "powerOn", 10: "powerOff"},
    12: {0: "power", 1: "up", 2: "down", 3: "left", 4: "right", 5: "play",
         6: "stop", 8: "clean", 9: "spotClean", 10: "fanSpeedUp",
         11: "fanTimer", 12: "dock"},
    13: {0: "power", 5: "fanIonizer", 8: "fanMode", 9: "fanSpeedUp",
         10: "modeSwitch", 11: "fanTimer", 12: "acLight"},
    14: {0: "power", 1: "fanSpeedUp", 2: "fanSpeedDown", 4: "fanTimer",
         5: "fanMode", 6: "acTempUp", 7: "acTempDown", 8: "fanOscillate",
         12: "sleep", 13: "acModeCool"},
}
MAX_KEY = {2: 23, 3: 23, 5: 23, 11: 23}


def hkdf(ikm, salt, info, length=32):
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:length]


def keys():
    h = hashlib.sha256()
    h.update(b"universalremotecontrol.app"); h.update(SALT2)
    ikm = KEY_PART_1 + h.digest()[:16]
    return (hkdf(ikm, b"zazaremote.pack.salt", b"zazaremote.cloud.v2"),
            hkdf(ikm, b"zazaremote.hmac.salt", b"zazaremote.cloud.hmac"))


def slugify(t):
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-") or "unknown"


def main():
    enc_key, hmac_key = keys()
    manifest = json.load(open(f"{REPO}/manifest.json"))
    existing = {p["id"] for p in manifest["packs"]}

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    brands_en = {}
    for r in con.execute("SELECT id, name, name_en FROM brand"):
        en = (r["name_en"] or "").strip()
        brands_en[r["id"]] = en if en else (r["name"] or "").strip()

    added = []
    rows = con.execute("""
        SELECT id, category_id, brand_id, brand_name, remote, remote_map,
               sub_cate, operator_name
        FROM remote_index WHERE status = 1""").fetchall()

    for row in rows:
        cat = CATEGORY.get(row["category_id"])
        if not cat: continue
        brand = brands_en.get(row["brand_id"]) or (row["brand_name"] or "").strip()
        operator = (row["operator_name"] or "").strip()
        if cat == "setTopBox" and operator: brand = operator
        if not brand: continue
        pack_id = f"irx-{row['id']}-{slugify(brand)[:24]}"
        if pack_id in existing: continue

        path = os.path.join(BINDIR, f"irda_{row['remote_map']}.bin")
        if not os.path.exists(path): continue
        sub = row["sub_cate"] if row["sub_cate"] in (1, 2) else 1
        is_ac = row["category_id"] == 1
        cmd = ([DUMP, "ac", path, str(sub), TMP] if is_ac else
               [DUMP, "cmd", path, str(sub),
                str(MAX_KEY.get(row["category_id"], 13)), TMP])
        if subprocess.run(cmd, capture_output=True, timeout=30).returncode: continue
        try: decoded = json.load(open(TMP))
        except (json.JSONDecodeError, OSError): continue

        codes = []
        if is_ac:
            codes = [{"key": t, "protocolName": "raw", "device": None,
                      "subdevice": None, "function": None,
                      "rawDurations": d, "frequency": 38000}
                     for t, d in decoded.items()]
        else:
            km = KEYMAP.get(row["category_id"], {})
            codes = [{"key": km[int(k)], "protocolName": "raw", "device": None,
                      "subdevice": None, "function": None,
                      "rawDurations": d, "frequency": 38000}
                     for k, d in decoded.items() if int(k) in km]
        if len(codes) < (5 if is_ac else 4): continue

        model = (row["remote"] or "").strip() or str(row["id"])
        pack = {"id": pack_id, "brand": brand, "category": cat,
                "model": f"{brand} {model}", "version": 1, "codes": codes}
        plaintext = json.dumps(pack, ensure_ascii=False,
                               separators=(",", ":")).encode()
        nonce = os.urandom(12)
        data = MAGIC + b"\x02" + nonce + AESGCM(enc_key).encrypt(nonce, plaintext, None)
        with open(f"{REPO}/packs/{pack_id}.json", "wb") as f:
            f.write(data)
        mac = hmac_mod.new(hmac_key, data, hashlib.sha256).hexdigest()
        added.append({"id": pack_id, "brand": brand, "category": cat,
                      "model": f"{brand} {model}", "version": 1,
                      "buttonCount": len(codes), "hmac": mac, "encrypted": True})

    if not added:
        print("no new packs")
        return

    manifest["packs"].extend(added)
    manifest["version"] += 1
    manifest["updatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(f"{REPO}/manifest.json", "w") as f:
        json.dump(manifest, f, ensure_ascii=False, separators=(",", ":"))
    print(f"added {len(added)} packs, manifest v{manifest['version']}")


if __name__ == "__main__":
    main()
