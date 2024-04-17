from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token,jwt_required
import datetime

app = Flask(__name__)
metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authdb.db'
app.config['SECRET_KEY'] = '49b77a70efb919bcf7d37b1b05c7d149'
app.config['JWT_ACCESS_TOKEN_EXPIRES']=datetime.timedelta(minutes=5)
app.config['JWT_COOKIE_SECURE']=False

db.init_app(app)
migrate = Migrate(app,db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)







