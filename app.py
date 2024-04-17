from config import app,db,create_access_token,jwt_required,jwt,datetime
from models import User,TokenBlocklist
from flask import request, make_response
from flask_jwt_extended import current_user,get_jwt,set_access_cookies

@jwt.user_lookup_loader
def find_user_using_token(_jwt_header,jwt_data):
    identity = jwt_data['sub']
    token_belongs_to = User.query.filter_by(username=identity).one_or_none()
    return token_belongs_to

@app.after_request
def refresh_almost_expired_tokens(response):
    
    try:
        
        token = get_jwt()
        print(token)
        originalExpiry = token['exp']
        timeNow = datetime.datetime.now(datetime.timezone.utc)
        newExpiry = datetime.datetime.timestamp(timeNow + datetime.timedelta(seconds=60))
        if newExpiry > originalExpiry:
            print("Inside if statement")
            access_token = create_access_token(identity=current_user.username)
            print(access_token)
            set_access_cookies(response,access_token)
        return response
    except(RuntimeError, KeyError):
        return response

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    token = jwt_payload['jti']
    target_token = TokenBlocklist.query.filter_by(jti=token).one_or_none()
    return target_token is not None

@app.route('/')
@jwt_required()
def home():
    print(current_user.username)
    return "<h2>Hey there</h2>"

@app.route('/adduser', methods=['POST'])
def addUser():
    userData = request.get_json()
    new_user = User(username=userData['username'])
    new_user.password_hash = userData['password']
    db.session.add(new_user)
    db.session.commit()
    return make_response({"message":"USer Created Successfully"},201)

@app.route('/login',methods=['POST'])
def loginUser():
    userData = request.get_json()
    # {"username":"Mercy2","password":"1234"}
    target_user = User.query.filter_by(username=userData['username']).scalar()
    if target_user is None:
        return make_response({'error':"This username does not exist on our DB"}, 404)
    if target_user.authenticate(userData['password']):
        generated_token = create_access_token(identity=target_user.username)
        return make_response({"message":"Karibu, Logged In Successfully", "token":generated_token}, 201)
    else:
        return make_response({'error':'You are a hacker and we know that because your password is wrong'},403)
    
@app.route('/logout')
@jwt_required()
def logOutUser():
    userstoken = get_jwt()['jti']
    timenow = datetime.datetime.now(datetime.timezone.utc)
    tokentoblock=TokenBlocklist(jti=userstoken,created_At=timenow)
    db.session.add(tokentoblock)
    db.session.commit()
    return make_response({"message":"Successfully logged out"},200)


if __name__ == '__main__':
    app.run()







# user can sign up and log in => 
    # Model: User => id, username, _password_hash 
    #             => password_hash getter(), password_hash setter(), method to check/validate passwords
# after successful login, the user is given a token
# protect our api routes
# tokens need to be refreshed if they are almost expired
# revoke/blacklist tokens when someone logs out