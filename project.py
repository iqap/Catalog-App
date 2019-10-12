#!/usr/bin/env python
from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open(
    "client_secrets.json", "r").read())["web"]["client_id"]
APPLICATION_NAME = "Catalog App"


# Connect to Database and create database session
engine = create_engine("sqlite:///catalog.db")
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route("/login")
def showLogin():
    state = "".join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32)
    )
    login_session["state"] = state
    # return "The current session state is %s" % login_session['state']
    return render_template("login.html", STATE=state)


@app.route("/gconnect", methods=["POST"])
def gconnect():
    # Validate state token
    if request.args.get("state") != login_session["state"]:
        response = make_response(json.dumps("Invalid state parameter."), 401)
        response.headers["Content-Type"] = "application/json"
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets("client_secrets.json", scope="")
        oauth_flow.redirect_uri = "postmessage"
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps("Failed to upgrade the authorization code."), 401
        )
        response.headers["Content-Type"] = "application/json"
        return response

    # Check that the access token is valid.
    a_t = credentials.access_token
    url = (
        "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s" % a_t
    )
    h = httplib2.Http()
    result = json.loads(h.request(url, "GET")[1])
    # If there was an error in the access token info, abort.
    if result.get("error") is not None:
        response = make_response(json.dumps(result.get("error")), 500)
        response.headers["Content-Type"] = "application/json"
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token["sub"]
    if result["user_id"] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401
        )
        response.headers["Content-Type"] = "application/json"
        return response

    # Verify that the access token is valid for this app.
    if result["issued_to"] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401
        )
        print "Token's client ID does not match app's."
        response.headers["Content-Type"] = "application/json"
        return response

    stored_access_token = login_session.get("access_token")
    stored_gplus_id = login_session.get("gplus_id")
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            "Current user is already connected."), 200)
        response.headers["Content-Type"] = "application/json"
        return response

    # Store the access token in the session for later use.
    login_session["access_token"] = credentials.access_token
    login_session["gplus_id"] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {"access_token": credentials.access_token, "alt": "json"}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session["username"] = data["email"]
    login_session["picture"] = data["picture"]
    login_session["email"] = data["email"]
    # ADD PROVIDER TO LOGIN SESSION
    login_session["provider"] = "google"

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session["user_id"] = user_id

    output = ""
    output += "<h1>Welcome, "
    output += login_session["username"]
    output += "!</h1>"
    output += '<img src="'
    output += login_session["picture"]
    output += ' " style = "width: 300px; height: 300px;border-radius:\
     150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session["username"])
    print "done!"
    return output


# User Helper Functions


def createUser(login_session):
    newUser = User(
        name=login_session["username"],
        email=login_session["email"],
        picture=login_session["picture"],
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session["email"]).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route("/gdisconnect")
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get("access_token")
    if access_token is None:
        response = make_response(json.dumps(
            "Current user not connected."), 401)
        response.headers["Content-Type"] = "application/json"
        return response
    url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % access_token
    h = httplib2.Http()
    result = h.request(url, "GET")[0]
    if result["status"] == "200":
        response = make_response(json.dumps("Successfully disconnected."), 200)
        response.headers["Content-Type"] = "application/json"
        return response
    else:
        response = make_response(
            json.dumps("Failed to revoke token for given user.", 400)
        )
        response.headers["Content-Type"] = "application/json"
        return response


# JSON APIs to view Category Information
@app.route("/catalog/<string:category_name>/JSON")
def categoryItemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CategoryItem).filter_by(
        category_id=category.id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route("/catalog/<string:category_name>/<string:item_name>/JSON")
def categoryItemJSON(category_name, item_name):
    _Item = session.query(CategoryItem).filter_by(name=item_name).one()
    return jsonify(_Item=_Item.serialize)


@app.route("/catalog/JSON")
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])


# Show all categories
@app.route("/")
@app.route("/catalog/")
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(CategoryItem).order_by(
        desc(CategoryItem.id)).limit(5)
    return render_template(
        "categories.html", categories=categories, items=items)


# Create a new category
@app.route("/catalog/new/", methods=["GET", "POST"])
def newCategory():
    if "username" not in login_session:
        return redirect("/login")
    if request.method == "POST":
        if request.form["name"]:
            request_name = request.form["name"]
            count = session.query(Category).filter_by(
                name=request_name).count()
            if count > 0:
                flash("Category %s already exists" % request_name)
            else:
                newCategory = Category(
                    name=request_name, user_id=login_session["user_id"]
                )
                session.add(newCategory)
                flash(
                    "New Category %s Successfully Created" % newCategory.name)
                session.commit()
        return redirect(url_for("showCategories"))
    else:
        return render_template("newCategory.html")


# Rename a category
@app.route("/catalog/<string:category_name>/rename/", methods=["GET", "POST"])
def editCategory(category_name):
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()
    if "username" not in login_session:
        return redirect("/login")
    if editedCategory.user_id != login_session["user_id"]:
        return '''<script>function myFunction() {alert('You are not
         authorized to edit this category. Please create your own
         category in order to edit.');}</script><body
         onload='myFunction()'>'''
    if request.method == "POST":
        if request.form["name"]:
            request_name = request.form["name"]
            count = session.query(
                Category).filter_by(name=request_name).count()
            if count > 0 and category_name != request_name:
                flash("Category %s already exists" % request_name)
            else:
                editedCategory.name = request_name
                flash("Category Successfully Edited %s" % editedCategory.name)
        return redirect(url_for("showCategories"))
    else:
        return render_template("renameCategory.html", category=editedCategory)


# Delete a category
@app.route(
    "/catalog/<string:category_name>/deleteCategory/", methods=["GET", "POST"])
def deleteCategory(category_name):
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()
    if "username" not in login_session:
        return redirect("/login")
    if categoryToDelete.user_id != login_session["user_id"]:
        return '''<script>function myFunction() {alert('You
         are not authorized to delete this category. Please
          create your own category in order to delete.');}
          </script><body onload='myFunction()'>'''
    if request.method == "POST":
        itemsToDelete = session.query(
            CategoryItem).filter_by(category_id=categoryToDelete.id).delete()
        session.commit()
        session.delete(categoryToDelete)
        flash("%s Successfully Deleted" % categoryToDelete.name)
        session.commit()
        return redirect(url_for("showCategories", category_name=category_name))
    else:
        return render_template(
            "deleteCategory.html", category=categoryToDelete)


# Show a category item
@app.route("/catalog/<string:category_name>/")
@app.route("/catalog/<string:category_name>/items/")
def showItem(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    items = session.query(
        CategoryItem).filter_by(category_id=category.id).all()
    is_valid_user = (
        "username" in login_session and creator.id == login_session["user_id"]
    )
    return render_template(
        "item.html",
        is_valid_user=is_valid_user,
        categories=categories,
        items=items,
        category=category,
        creator=creator,
    )


# Create a new item
@app.route("/catalog/<string:category_name>/new/", methods=["GET", "POST"])
def newCategoryItem(category_name):
    if "username" not in login_session:
        return redirect("/login")
    category = session.query(Category).filter_by(name=category_name).one()
    if login_session["user_id"] != category.user_id:
        return '''<script>function myFunction() {alert('You
         are not authorized to add item items to this category.
          Please create your own category in order to add items.
          ');}</script><body onload='myFunction()'>'''
    if request.method == "POST":
        request_name = request.form["name"]
        count = session.query(
            CategoryItem).filter_by(name=request_name).count()
        if count > 0:
            flash("Item %s already exists" % request_name)
        else:
            category = session.query(
                Category).filter_by(name=category_name).one()
            newItem = CategoryItem(
                name=request.form["name"],
                description=request.form["description"],
                category=category,
                user_id=category.user_id,
            )
            session.add(newItem)
            session.commit()
            flash("New Item %s Item Successfully Created" % (newItem.name))
        return redirect(url_for("showItem", category_name=category_name))
    else:
        return render_template(
            "newcategoryitem.html", category_name=category_name)


# Edit item
@app.route("/catalog/<string:item_name>/edit", methods=["GET", "POST"])
def editCategoryItem(item_name):
    if "username" not in login_session:
        return redirect("/login")
    categories = session.query(Category).order_by(asc(Category.name))
    editedItem = session.query(CategoryItem).filter_by(name=item_name).one()
    category = session.query(
        Category).filter_by(id=editedItem.category_id).one()
    categories = (
        session.query(Category)
        .filter_by(user_id=login_session["user_id"])
        .order_by(asc(Category.name))
    )
    if login_session["user_id"] != category.user_id:
        return '''<script>function myFunction() {alert
        ('You are not authorized to edit item items to
         this category. Please create your own category in
          order to edit items.');}</script><body
           onload='myFunction()'>'''
    if request.method == "POST":
        if request.form["name"]:
            request_name = request.form["name"]
            count = session.query(
                CategoryItem).filter_by(name=request_name).count()
            if count > 0 and item_name != request_name:
                flash("Item %s already exists" % request_name)
            else:
                editedItem.name = request.form["name"]
                flash("Item Item Successfully Edited")

        if request.form["description"]:
            editedItem.description = request.form["description"]

        selected_category = (
            session.query(
                Category).filter_by(name=request.form["category"]).one()
        )
        if (
            request.form["category"]
            and selected_category.user_id == login_session["user_id"]
        ):
            new_category = (
                session.query(
                    Category).filter_by(name=request.form["category"]).one()
            )
            editedItem.category = new_category

        session.add(editedItem)
        session.commit()
        return redirect(url_for("showItem", category_name=category.name))
    else:
        return render_template(
            "editcategoryitem.html", categories=categories, item=editedItem
        )


# View item
@app.route(
    "/catalog/<string:category_name>\
    /<string:item_name>/", methods=["GET", "POST"]
)
def viewCategoryItem(category_name, item_name):
    item = session.query(CategoryItem).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    is_valid_user = (
        "username" in login_session and creator.id == login_session["user_id"]
    )
    return render_template(
        "viewCategoryItem.html",
        item=item,
        category=category,
        is_valid_user=is_valid_user,
    )


# Delete item
@app.route("/catalog/<string:item_name>/delete", methods=["GET", "POST"])
def deleteCategoryItem(item_name):
    if "username" not in login_session:
        return redirect("/login")
    itemToDelete = session.query(CategoryItem).filter_by(name=item_name).one()
    category = session.query(
        Category).filter_by(id=itemToDelete.category.id).one()
    if login_session["user_id"] != category.user_id:
        return '''<script>function myFunction() {alert('You are not
         authorized to delete items to this category. Please create
          your own category in order to delete items.');}</script><body
           onload='myFunction()'>'''
    if request.method == "POST":
        session.delete(itemToDelete)
        session.commit()
        flash("Item Successfully Deleted")
        return redirect(url_for("showItem", category_name=category.name))
    else:
        return render_template("deleteCategoryItem.html", item=itemToDelete)


# Disconnect based on provider
@app.route("/disconnect")
def disconnect():
    if "provider" in login_session:
        if login_session["provider"] == "google":
            gdisconnect()
            del login_session["gplus_id"]
            del login_session["access_token"]
        del login_session["username"]
        del login_session["email"]
        del login_session["picture"]
        del login_session["user_id"]
        del login_session["provider"]
        flash("You have successfully been logged out.")
        return redirect(url_for("showCategories"))
    else:
        flash("You were not logged in")
        return redirect(url_for("showCategories"))


if __name__ == "__main__":
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host="0.0.0.0", port=5000)
