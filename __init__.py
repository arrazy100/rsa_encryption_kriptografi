from flask import Flask

def create_app():
    app = Flask(__name__)

    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app