import pytest

from blackbox import keys
from blackbox.log import EventLog


@pytest.fixture
def key():
    return keys.generate()


@pytest.fixture
def sample_log(tmp_path, key):
    """A small incident: genesis plus three events, with fixed timestamps."""
    path = tmp_path / "incident.log"
    log = EventLog(path, key, device="arm-01", fsync=False)
    log.append("joint_state", {"joint": "elbow", "position": 1.25, "velocity": 0.0}, ts="2026-10-11T12:00:00.000000Z")
    log.append("estop", {"source": "operator", "reason": "person in cell"}, ts="2026-10-11T12:00:01.500000Z")
    log.append("fault", {"code": "E-217", "detail": "torque limit"}, ts="2026-10-11T12:00:01.750000Z")
    return path
