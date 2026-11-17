"""Zoológico de detectores: ligeros (candidatos para edge) y pesados (línea base).

Interfaz común:
    fit(X, y)        y=None para los no supervisados (solo tráfico normal)
    calibrate(Xn)    fija el umbral con tráfico normal de calibración (FPR objetivo)
    score(X)         puntaje de anomalía (mayor = más sospechoso)
    predict(X)       0/1
"""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

TARGET_FPR = 0.005

# Rasgos de comportamiento que usa la línea base estadística por perfil
PROFILE_FEATURES = ["w1_flows", "w1_uniq_dst", "w1_uniq_dport", "w1_syn_only", "w1_small", "w1_ext",
                    "w10_uniq_dst", "w10_syn_only", "log_bytes", "dst_ext", "p_other"]
def role_cols(X):
    """Columnas de rol (r_*): dependen del contexto de red (campus o dataset público)."""
    return [c for c in X.columns if c.startswith("r_")]


class Detector:
    name = "base"
    family = "ligero"
    supervised = False
    threshold = 0.5

    def calibrate(self, X_normal):
        if not self.supervised:
            self.threshold = float(np.quantile(self.score(X_normal), 1 - TARGET_FPR))
        return self

    def predict(self, X):
        return (self.score(X) > self.threshold).astype(np.int8)


class ProfileZScore(Detector):
    """Detección estadística: z-score máximo respecto al perfil del rol del origen."""
    name = "Reglas z-score por perfil"

    def fit(self, X, y=None):
        cols = X.columns
        self.idx = [cols.get_loc(c) for c in PROFILE_FEATURES]
        rc = role_cols(X)
        roles = X[rc].to_numpy().argmax(axis=1)
        V = X.to_numpy()[:, self.idx]
        self.mu = np.zeros((len(rc), len(self.idx)), np.float32)
        self.sd = np.ones_like(self.mu)
        for r in range(len(rc)):
            m = roles == r
            if m.sum() > 10:
                self.mu[r] = V[m].mean(axis=0)
                self.sd[r] = V[m].std(axis=0) + 0.05
        self.role_idx = [cols.get_loc(c) for c in rc]
        return self

    def score(self, X):
        A = X.to_numpy() if hasattr(X, "to_numpy") else X
        roles = A[:, self.role_idx].argmax(axis=1)
        return np.abs((A[:, self.idx] - self.mu[roles]) / self.sd[roles]).max(axis=1)


class IForest(Detector):
    """Isolation Forest sobre rasgos de comportamiento + rol (con todos los rasgos
    los indicadores binarios diluyen los cortes aleatorios: ver la ablación)."""
    name = "Isolation Forest"
    behavioral = True

    def __init__(self, seed=0):
        self.m = IsolationForest(n_estimators=100, max_samples=256, random_state=seed, n_jobs=1)

    def _sel(self, X):
        return X[PROFILE_FEATURES + role_cols(X)] if self.behavioral else X

    def fit(self, X, y=None):
        self.m.fit(self._sel(X))
        return self

    def score(self, X):
        return -self.m.score_samples(self._sel(X))


class IForestAllFeatures(IForest):
    """Ablación: Isolation Forest con todas las características."""
    name = "Isolation Forest (todos los rasgos, ablación)"
    behavioral = False


class TinyAutoencoder(Detector):
    """Autoencoder pequeño (cuello de botella de 6 neuronas); puntaje = error de reconstrucción."""
    name = "Autoencoder ligero"

    def __init__(self, seed=0):
        self.sc = StandardScaler()
        self.m = MLPRegressor(hidden_layer_sizes=(16, 6, 16), activation="relu", max_iter=60,
                              early_stopping=True, random_state=seed)

    def fit(self, X, y=None):
        Z = self.sc.fit_transform(X)
        self.m.fit(Z, Z)
        return self

    def score(self, X):
        Z = self.sc.transform(X)
        return ((self.m.predict(Z) - Z) ** 2).mean(axis=1)


class SmallTree(Detector):
    name = "Árbol de decisión"
    supervised = True

    def __init__(self, seed=0):
        self.m = DecisionTreeClassifier(max_depth=10, class_weight="balanced", random_state=seed)

    def fit(self, X, y):
        self.m.fit(X, y)
        return self

    def score(self, X):
        return self.m.predict_proba(X)[:, 1]


class BigForest(Detector):
    name = "Random Forest (300 árboles)"
    family = "pesado"
    supervised = True

    def __init__(self, seed=0):
        self.m = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=1)

    def fit(self, X, y):
        self.m.fit(X, y)
        return self

    def score(self, X):
        return self.m.predict_proba(X)[:, 1]


class DeepMLP(Detector):
    name = "MLP profunda (256-128-64)"
    family = "pesado"
    supervised = True

    def __init__(self, seed=0):
        self.sc = StandardScaler()
        self.m = MLPClassifier(hidden_layer_sizes=(256, 128, 64), max_iter=40, early_stopping=True,
                               random_state=seed)

    def fit(self, X, y):
        self.m.fit(self.sc.fit_transform(X), y)
        return self

    def score(self, X):
        return self.m.predict_proba(self.sc.transform(X))[:, 1]


class LightForest(Detector):
    """Bosque ligero: punto medio entre el árbol (inestable ante deriva) y el RF de 300.

    Configuración fijada a priori por la restricción del edge (~1 MB), no ajustada con la prueba.
    """
    name = "Bosque ligero (10 árboles)"
    supervised = True

    def __init__(self, seed=0):
        self.m = RandomForestClassifier(n_estimators=10, max_depth=10, min_samples_leaf=50, max_features="sqrt",
                                        class_weight="balanced", random_state=seed, n_jobs=1)

    def fit(self, X, y):
        self.m.fit(X, y)
        return self

    def score(self, X):
        return self.m.predict_proba(X)[:, 1]


class HybridTreeAE(Detector):
    """Árbol (ataques conocidos, casi sin falsos positivos) OR autoencoder (novedad).

    El puntaje combina ambos en una escala donde 0.5 es el umbral de cada uno.
    """
    name = "Híbrido (árbol + autoencoder)"
    supervised = True

    def __init__(self, seed=0):
        self.tree = SmallTree(seed)
        self.ae = TinyAutoencoder(seed)

    def fit(self, X, y):
        self.tree.fit(X, y)
        self.ae.fit(X[np.asarray(y) == 0])
        return self

    def calibrate(self, X_normal):
        self.ae.threshold = float(np.quantile(self.ae.score(X_normal), 1 - TARGET_FPR))
        return self

    def score(self, X):
        return np.maximum(self.tree.score(X), 0.5 * self.ae.score(X) / self.ae.threshold)


ALL = [ProfileZScore, IForest, IForestAllFeatures, TinyAutoencoder, SmallTree, LightForest, HybridTreeAE,
       BigForest, DeepMLP]


def build(cls, seed):
    return cls() if cls is ProfileZScore else cls(seed=seed)
