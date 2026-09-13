from ephemguard.security.path_guard import is_confined

def test_confined(tmp_path):
    assert is_confined(tmp_path, "src/a.py")

def test_traversal(tmp_path):
    assert not is_confined(tmp_path, "../secret.txt")

def test_confined_relative(tmp_path):
    assert is_confined(tmp_path, "src/a.py")

def test_traversal_blocked(tmp_path):
    assert not is_confined(tmp_path, "../secret.txt")

