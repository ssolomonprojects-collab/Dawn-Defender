import sys
import os

# Add root project directory to sys.path so Vercel can locate app modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app

app = create_app()
