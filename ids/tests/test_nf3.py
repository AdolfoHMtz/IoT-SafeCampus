"""El adaptador NF3 se prueba con un CSV falso que imita el formato de NF-ToN-IoT-v3."""
import zipfile

import numpy as np
import pandas as pd
import pytest

from safecampus import nf3
from safecampus.features import RFC1918, NetContext, extract

DAY_MS = 86_400_000


def fake_nf3(tmp_path):
    rng = np.random.default_rng(0)
    rows = []
    base = 1_554_076_800_000          # 2019-04-01 00:00 UTC (ToN-IoT es de 2019)
    for day in range(6):              # días 0-2 benignos; 3-5 con ataques
        for k in range(400):
            t = base + day * DAY_MS + int(rng.integers(0, DAY_MS))
            rows.append((t, "192.168.1.%d" % rng.integers(2, 40), "192.168.1.1", 443, "Benign", 0, 24))
        if day >= 3:
            attack = ["scanning", "ddos", "xss"][day - 3]
            t0 = base + day * DAY_MS + 3_600_000
            for k in range(300):
                rows.append((t0 + k * 500, "192.168.1.30", "192.168.1.%d" % (k % 200 + 2),
                             int(rng.integers(1, 1024)), attack, 1, 2))
    df = pd.DataFrame(rows, columns=["FLOW_START_MILLISECONDS", "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_DST_PORT",
                                     "Attack", "Label", "CLIENT_TCP_FLAGS"])
    df["FLOW_DURATION_MILLISECONDS"] = 20
    df["L4_SRC_PORT"] = 50000
    df["PROTOCOL"] = 6
    df["IN_PKTS"] = 3
    df["IN_BYTES"] = 300
    df["L7_PROTO"] = 7.0          # columna extra que el adaptador debe ignorar
    path = tmp_path / "NF-ToN-IoT-v3.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("NF-ToN-IoT-v3.csv", df.sample(frac=1, random_state=0).to_csv(index=False))
    return path


def test_profile_and_build_follow_protocol(tmp_path, monkeypatch):
    monkeypatch.setattr(nf3, "PROFILE", tmp_path / "profile.csv")
    monkeypatch.setattr(nf3, "SUBSET", tmp_path / "subset.pkl")
    monkeypatch.setattr(nf3, "CHUNK", 500)
    path = fake_nf3(tmp_path)

    nf3.profile(path)
    p = pd.read_csv(nf3.PROFILE)
    assert sorted(p["day"].unique()) == [1, 2, 3, 4, 5, 6]
    assert set(p["attack"]) == {"normal", "scanning", "ddos", "xss"}

    nf3.build(benign_cap=10**9, cal_cap=10**9, attack_cap=10**9, n_seen=2, path=path)
    df = pd.read_pickle(nf3.SUBSET)
    by = df.groupby("split")["attack"].apply(set)
    # división temporal: fit ve scanning y ddos; xss solo aparece en prueba
    assert by["fit"] == {"normal", "scanning", "ddos"} and by["cal"] == {"normal"}
    assert by["test"] == {"normal", "xss"}
    assert df.loc[df["split"] == "fit", "ts"].max() < df.loc[df["split"] == "cal", "ts"].min()
    assert df.loc[df["split"] == "cal", "ts"].max() < df.loc[df["split"] == "test", "ts"].min()
    # bloques completos: los 300 flujos de cada ataque se conservan juntos
    assert (df["attack"] == "scanning").sum() == 300
    assert df["ts"].between(1.55e9, 1.56e9).all() and (df["duration"] == 0.02).all()

    X = extract(df, NetContext(internal_prefixes=RFC1918))
    assert np.isfinite(X.to_numpy()).all()
    assert {"r_internal", "r_external"} <= set(X.columns) and X["src_ext"].sum() == 0
    scan = (df["attack"] == "scanning").to_numpy()
    assert X.loc[scan, "w1_uniq_dst"].min() > X.loc[df["label"].to_numpy() == 0, "w1_uniq_dst"].max()


def test_missing_dataset_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(nf3, "EXTERNAL", tmp_path)
    with pytest.raises(SystemExit, match="No encontré el dataset"):
        nf3.find_dataset()
