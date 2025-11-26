"""Simple test to verify pytest is working"""

def test_simple():
    """Basic test that always passes"""
    assert True

def test_addition():
    """Test basic math"""
    assert 1 + 1 == 2
    
def test_string():
    """Test string operations"""
    assert "hello".upper() == "HELLO"

print("✓ Test file loaded successfully")
