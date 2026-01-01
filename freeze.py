from app import app
try:
    from flask_frozen import Freezer
except ImportError:
    import sys
    print("Missing dependency: Flask-Frozen (module 'flask_frozen'). Install with:")
    print("    python -m pip install Frozen-Flask")
    sys.exit(1)

freezer = Freezer(app)
if __name__ == "__main__":
    freezer.freeze()   # outputs to ./build by default