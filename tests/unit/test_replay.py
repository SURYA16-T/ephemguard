from ephemguard.security.replay_guard import ReplayGuard

def test_replay_guard():
    g = ReplayGuard()
    assert g.claim("x")
    assert not g.claim("x")
