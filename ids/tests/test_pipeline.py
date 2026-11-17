import numpy as np
import pandas as pd
import pytest

from safecampus import models
from safecampus.edge import EdgeGateway, categorize, isolation_commands
from safecampus.features import extract
from safecampus.generator import DAY, ScenarioConfig, generate
from safecampus.inventory import load_inventory


@pytest.fixture(scope="module")
def inv():
    return load_inventory()


@pytest.fixture(scope="module")
def data(inv):
    return generate(ScenarioConfig(seed=1), inv)


def test_inventory_matches_topology(inv):
    s = inv["SENS-A1"]
    assert (s.ip, s.vlan, s.role, s.switch, s.port) == ("10.10.10.11", 10, "sensor", "SW-AULA1", "FastEthernet0/2")
    assert inv["CAM-A4"].switch == "SW-AULA4" and inv["PC-ATACANTE"].vlan == 40
    assert len([d for d in inv.values() if d.role in ("sensor", "camera")]) == 40  # 10 aulas x 4 IoT


def test_generator_is_reproducible(inv, data):
    again = generate(ScenarioConfig(seed=1), inv)
    pd.testing.assert_frame_equal(data, again)


def test_clean_days_have_no_attacks_and_exfil_is_unseen(data):
    assert data.loc[data["day"].isin([0, 1]), "label"].sum() == 0
    seen = set(data.loc[data["day"] == 2, "attack"])
    assert "exfil" not in seen and "exfil" in set(data.loc[data["day"] == 3, "attack"])
    assert (data["ts"] >= 0).all() and (data["ts"] < 4 * DAY).all()


def test_features_are_finite_and_capture_scans(inv, data):
    day3 = data[data["day"] == 3]
    X = extract(day3, inv)
    assert len(X) == len(day3) and np.isfinite(X.to_numpy()).all()
    scan = (day3["attack"] == "scan").to_numpy()
    normal = (day3["label"] == 0).to_numpy()
    assert X.loc[scan, "w10_uniq_dst"].median() > X.loc[normal, "w10_uniq_dst"].quantile(0.99)


def test_unsupervised_threshold_respects_target_fpr(inv, data):
    X = extract(data[data["day"] <= 1], inv)
    day = data.loc[data["day"] <= 1, "day"].to_numpy()
    det = models.ProfileZScore().fit(X[day == 0]).calibrate(X[day == 1])
    assert det.predict(X[day == 1]).mean() == pytest.approx(models.TARGET_FPR, abs=0.002)


def test_host_macro_fpr_is_not_dominated_by_a_noisy_host():
    from safecampus.experiment import operational
    # host A: 1000 flujos benignos, todos marcados; hosts B y C: 10 benignos cada uno, ninguno marcado
    src = ["10.0.0.1"] * 1000 + ["10.0.0.2"] * 10 + ["10.0.0.3"] * 10 + ["10.0.0.9"] * 5
    df = pd.DataFrame({"src_ip": src, "ts": np.arange(len(src), dtype=float),
                       "label": [0] * 1020 + [1] * 5, "attack": ["normal"] * 1020 + ["scan"] * 5})
    p = np.array([1] * 1000 + [0] * 20 + [1] * 5, dtype=np.int8)
    ops, _ = operational(df, p)
    assert ops["fpr_clean_hosts"] == pytest.approx(1000 / 1020)
    assert ops["fpr_host_macro"] == pytest.approx(1 / 3)


def test_isolation_commands_target_real_port(inv):
    cmds = "\n".join(isolation_commands(inv["CAM-A4"], "10.10.99.100"))
    assert "SW-AULA4(config)# interface FastEthernet0/3" in cmds and "switchport access vlan 99" in cmds
    assert "10.10.99.100/24" in cmds


def test_quarantine_ips_never_collide(inv):
    # CAM-A2 (10.10.20.12) y PROTO-LAB2 (10.10.40.12) comparten último octeto
    gw = EdgeGateway(models.ProfileZScore(), inv)
    gw.det.predict = lambda X: np.ones(len(X), dtype=np.int8)     # todo marcado
    for minute in range(2):
        flows = pd.DataFrame([{"ts": minute * 60.0 + i, "duration": 0.0, "src_ip": ip, "dst_ip": "10.10.10.99",
                               "src_port": 50000, "dst_port": 23, "proto": 6, "packets": 1, "bytes": 44,
                               "tcp_flags": 2} for ip in ("10.10.20.12", "10.10.40.12") for i in range(5)])
        gw.process_minute(flows)
    qips = [q["ip_cuarentena"] for q in gw.quarantined.values()]
    assert len(qips) == 2 and len(set(qips)) == 2


def test_categorize_nocturnal_exfiltration():
    flows = pd.DataFrame({"ts": [2.5 * 3600] * 3, "src_ip": ["10.10.20.14"] * 3,
                          "dst_ip": ["203.0.113.10", "10.10.50.10", "10.10.60.20"], "dst_port": [443, 1883, 0],
                          "bytes": [9e6, 500, 74], "tcp_flags": [24, 24, 0]})
    assert categorize(flows).startswith("Posible exfiltración")
