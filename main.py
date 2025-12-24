from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import os
from typing import List

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''



app = Flask(__name__)
# Replaced with environment variable for security
# - Old version stores secret in code → bad for GitHub/sharing
# - New version pulls from os.environ → keeps secret out of code
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '8BYkEfBA6O6donzWlSihBXox7C0sKR6b')
ckeditor = CKEditor(app)
Bootstrap5(app)


# ===================================================================
# GRAVATAR
# ===================================================================

# GRAVATAR CONFIGURATION
# Flask-Gravatar generates profile pictures from email addresses.
# Parameters:
# - size=100: Default image size (can be overridden in templates)
# - rating='g': Only safe images (no adult content)
# - default='retro': Fallback image if user has no Gravatar (other options: 'monsterid', 'wavatar', etc.)
# - force_default=False: Use default only if no Gravatar exists
# - force_lower=False: Don't force lowercase email (Gravatar is case-insensitive anyway)
# - use_ssl=True: Use HTTPS for secure image loading
# - base_url: Direct link to Gravatar service
#
# Usage in templates:
# {{ gravatar(user.email, size=50) }} → shows 50x50 image for that email
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=True,
                    base_url='https://www.gravatar.com/avatar/')



# ===================================================================
# ADMIN DECORATOR
# ===================================================================
def admin_only(function_to_decorate):
    """
    Custom Flask decorator: Restricts access to routes ONLY for the admin user (id == 1).

    How it works — step by step:

    1. When Python sees @admin_only above a route (e.g. add_new_post),
       it immediately calls this function and passes the original route function.

    2. This decorator creates a "wrapper" function (decorated_function) that:
       • Captures all arguments (*args, **kwargs) the original route might receive
       • Runs security checks first
       • If user is not logged in OR not admin → returns HTTP 403 Forbidden
       • If user is admin → runs the ORIGINAL function with all its original arguments

    3. @wraps(function_to_decorate) preserves the original function's name and docstring
       so Flask still sees it as "add_new_post", not "decorated_function".
       This is CRITICAL for Flask routing, url_for(), debugging, and error logs.

    4. The line "return decorated_function" happens ONCE at startup:
       It replaces the original route with our secure wrapper.

    5. The line "return function_to_decorate(*args, **kwargs)" happens EVERY request:
       It runs the original route (e.g. shows the "New Post" form) and returns its result.
    """
    @wraps(function_to_decorate)
    def decorated_function(*args, **kwargs):
        # If no user logged in → 403
        if not current_user.is_authenticated:
            return abort(403)
        # If logged in but not admin → 403
        if current_user.id != 1:
            return abort(403)
        # Otherwise → proceed
        return function_to_decorate(*args, **kwargs)
    return decorated_function # → Wrapper created and returned. Original function is now replaced forever.


# ===================================================================
# FLASK-LOGIN CUSTOMIZATION — Friendly login experience
# ===================================================================
# TODO: Configure Flask-Login
# FLASK-LOGIN CONFIGURATION
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'          # Redirect unauthenticated users here
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info" # ← Custom flash message shown after redirect
                                                                     #     (replaces the default 401 text)


@login_manager.user_loader
def load_user(user_id):
    """
    Required by Flask-Login.
    Tells Flask-Login how to retrieve a user from the database using the user ID stored in the session.
    """
    return db.session.get(User, int(user_id))


# ===================================================================
# Custom base class for declarative models (required in SQLAlchemy 2.0+ style)
# CREATE DATABASE
# ===================================================================

class Base(DeclarativeBase):
    pass
# Replaced with environment variable for flexibility/security
# - Old version hardcodes SQLite path → won't work on Render (uses PostgreSQL)
# - New version pulls from os.environ → easy to switch databases without changing code
# - Fallback 'sqlite:///posts.db' is for local development only
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# ------------------------------------------------------------------
# DATABASE MODEL — User (SQLAlchemy)
# ------------------------------------------------------------------
# two lines that talk to each other:
    # In User class
    #   posts = relationship("BlogPost", back_populates="author")

    # # In BlogPost class
    #   author = relationship("User", back_populates="posts")

# TODO: Create a User table for all your registered users.
# Create a User table for all your registered users
class User(UserMixin, db.Model):
    """
        UserMixin is a built-in Flask-Login class that automatically adds the required
        methods and attributes for Flask-Login to work:
        - is_authenticated: True if the user is logged in
        - is_active: True if the account is active
        - is_anonymous: False for real users
        - get_id(): Returns the user's unique ID as a string
        Without this, Flask-Login wouldn't know how to handle our User objects.

        Purpose:
          - Stores user accounts for registration and login
          - Inherits from Flask-Login's UserMixin → provides is_authenticated, is_active, etc.
          - Password is NEVER stored in plain text → always hashed with PBKDF2 + salt

        SQLAlchemy model for users.

        Key relationships:
        - One User → Many BlogPosts (a user can write many posts).
          → Access: user.posts → List of BlogPost objects.
          → Example: for post in user.posts: print(post.title)
        - One User → Many Comments (a user can leave many comments).
          → Access: user.comments → List of Comment objects.
          → Example: for comment in user.comments: print(comment.text)

        How relationships work:
        - No foreign key here (User is the "parent").
        - The "posts" and "comments" fields are Python shortcuts created by relationship().
        - back_populates tells SQLAlchemy to connect to the "author" field in BlogPost/Comment.

        """
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # ONE TO MANY: One User → Many BlogPosts
    # back_populates tells SQLAlchemy: "this connects to the 'author' field in BlogPost"
    posts: Mapped[List["BlogPost"]] = relationship("BlogPost", back_populates="author")
    # ONE TO MANY: One User → Many Comments
    # back_populates tells SQLAlchemy: "this connects to the 'author' field in Comment"
    comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="author")

# CONFIGURE TABLES
class BlogPost(db.Model):
    """
    SQLAlchemy model for blog posts.

    Key relationships:
    - One BlogPost → One User (author).
      → Access: post.author → Single User object (not a list).
      → Example: print(post.author.name)  # "Héctor"
      → Why no List? A post has exactly one author.
    - One BlogPost → Many Comments (a post can have many comments).
      → Access: post.comments → List of Comment objects.
      → Example: for comment in post.comments: print(comment.text)

    How relationships work:
    - Foreign key (author_id): Stores the User's id (e.g., 1) in the database — the "glue" that links tables.
      - Without it, no real connection; just strings/numbers.
      - Syntax: ForeignKey("users.id") → points to "id" column in "users" table.
    - The "author" field is a Python shortcut: post.author → auto-looks up User by author_id.
    - back_populates connects back to "posts" in User and "comments" in Comment.

    Accessing attributes:
    - post.title → direct string (column) → {{ post.title }}
    - post.author.name → relationship to User object → dot into object attributes.
      - Why? author is an object, not a string — gives access to all User info (name, email, etc.).
    """
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # Foreign Key: links each post to a user on the users table database from the User class
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)#Identifys the name of the column to link on parent db

    # Relationship: allows post.author → gives you the User object
    author: Mapped["User"] = relationship("User", back_populates="posts")
    # ONE TO MANY: One BlogPost → Many Comments
    # back_populates tells SQLAlchemy: "this connects to the 'post' field in Comment"
    comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="post")



class Comment(db.Model):
    """
        SQLAlchemy model for comments.

        Key relationships:
        - One Comment → One User (author).
          → Access: comment.author → Single User object.
          → Example: print(comment.author.name)  # "Héctor"
          → Why no List? A comment has exactly one author.
        - One Comment → One BlogPost (the post it's on).
          → Access: comment.post → Single BlogPost object.
          → Example: print(comment.post.title)  # "My Blog Post"

        How relationships work:
        - Foreign keys (author_id, post_id): Store IDs (e.g., author_id=1, post_id=3) — the "glue".
          - Without them, no links; just isolated comments.
          - Syntax: ForeignKey("users.id") / ForeignKey("blog_posts.id") → point to IDs in other tables.
        - "author" and "post" fields are Python shortcuts: comment.author → auto-lookup by ID.
        - back_populates connects back to "comments" in User/BlogPost.

        Accessing attributes:
        - comment.text → direct string (column) → {{ comment.text|safe }}
        - comment.author.name → relationship to User → dot into object.
        - comment.post.title → relationship to BlogPost → dot into object.
          - Why? Relationships give full objects, not strings — unlocks all related data.
        """
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # One Comment → One Author (User)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False) #Identifys the name of the column to link on parent db
    author: Mapped["User"] = relationship("User", back_populates="comments")

    # One Comment → One BlogPost
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"), nullable=False)#Identifys the name of the column to link on parent db
    post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")


# ------------------------------------------------------------------
# CREATE TABLES
# ------------------------------------------------------------------
with app.app_context():
    db.create_all()
# ------------------------------------------------------------------
# ROUTES
# ------------------------------------------------------------------

# TODO: Use Werkzeug to hash the user's password when creating a new user.
# Register new users into the User database
@app.route('/register', methods=["GET", "POST"])
def register():
    """
        Handle user registration.

        - GET request: Displays the registration form (RegisterForm from forms.py).
        - POST request: Validates submitted data using WTForms.
          • Checks if the email already exists in the database.
          • Hashes the password using Werkzeug's generate_password_hash (PBKDF2 + salt).
          • Creates a new User instance (SQLAlchemy model).
          • Saves the user to the SQLite database (posts.db → users table).
          • Shows success message and redirects to home page.

        Uses:
          - RegisterForm (WTForms) → input validation and CSRF protection
          - User model (SQLAlchemy + Flask-Login UserMixin) → database storage
          - Flask flash → user feedback
          - generate_password_hash → secure password storage (never stores plain text)

        Returns:
            - Rendered register.html template with form (on GET or validation failure)
            - Redirect to home page on successful registration
        """
    form = RegisterForm()
    if form.validate_on_submit():

        # ----------------------------------
        # Check if email already exists
        if db.session.execute(db.select(User).where(User.email == form.email.data)).scalar():
            flash("You've already signed up with that email. Log in instead!")
            return redirect(url_for("login"))
        # ----------------------------------

        # Create hashed password
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        # Create new user
        new_user = User(
            email=form.email.data,
            password=hash_and_salted_password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()

        # Log the user in immediately after registration
        login_user(new_user)
        # flash() sends a one-time message to the user that will be displayed
        # on the next page load (and then disappears). It's perfect for login/register
        # feedback like "Wrong password" or "Email already exists".
        # The message is stored in the session and shown using get_flashed_messages()
        # in the template.
        flash("Account created successfully! You are now logged in.", "success")

        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    """
    Handle user login.

    GET  → Renders the login form
    POST →
        • Validates form input (email + password required)
        • Looks up user by email in the database
        • Verifies password using check_password_hash()
        • If credentials are correct → calls login_user(user) to create session
        • If wrong → flashes appropriate error and redisplays form
    """
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        # Email doesn't exist
        if not user:
            flash("That email does not exist. Please try again or register.", "error")
            return redirect(url_for("login"))

        # Wrong password
        elif not check_password_hash(user.password, password):
            flash("Password incorrect. Please try again.", "error")
            return redirect(url_for("login"))

        # Success → log the user in
        else:
            # This function is provided by the Flask-Login extension.
            login_user(user)
            flash(f"Welcome back, {user.name}!", "success")
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    """
        Logs out the current user, clears their session, flashes a confirmation
        message, and redirects them to the homepage (all posts view).
        """
    # This function is provided by the Flask-Login extension.
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    """
        Displays a single blog post and handles new comment submissions.

        Flow:
        - GET request: Loads the post and shows the comment form.
        - POST request (form submit):
            • Validates the form.
            • Checks if user is logged in (current_user from Flask-Login).
            • If not logged in → flashes message and redirects to login.
            • If logged in → creates new Comment object:
                - text: from CKEditor field
                - author: current_user (Flask-Login provides this object)
                - post: the requested_post (links via relationship)
            • Saves to database and redirects back to same post (to see new comment).

        Why author=current_user and post=requested_post work:
            - SQLAlchemy sees these as relationship objects → automatically sets the foreign keys
              (author_id = current_user.id, post_id = post.id).
            - No need to manually set author_id/post_id.

        Returns:
            - render_template("post.html") with the post and empty form on GET.
            - redirect to same post on successful comment.
        """
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.", "warning")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment.data,
            author=current_user, #from flask_login extension
            post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, form=comment_form, gravatar=gravatar)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

# Main guard: Runs the Flask development server only if this file is executed directly
# - debug=False for production-like behavior (no detailed errors shown to users)
# - port=5002 to avoid conflicts with other apps (default is 5000)
if __name__ == "__main__":
    app.run(debug=False, port=5002)

