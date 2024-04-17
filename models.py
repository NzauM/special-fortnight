from config import db, bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    _password_hash = db.Column(db.String, nullable=False)

    @hybrid_property
    def password_hash(self):
        return self._password_hash
    
    @password_hash.setter
    def password_hash(self,userpassword):
        hashed_value = bcrypt.generate_password_hash(userpassword.encode('utf-8'))
        self._password_hash = hashed_value.decode('utf-8')

    def authenticate(self,userpassword):
        is_valid = bcrypt.check_password_hash(self._password_hash, userpassword.encode('utf-8'))
        return is_valid
    
class TokenBlocklist(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    jti=db.Column(db.String, nullable=False, index=True)
    created_At = db.Column(db.String, nullable=False, )




    

