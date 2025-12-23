from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_ckeditor import CKEditorField
from wtforms.validators import URL


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users

class RegisterForm(FlaskForm):
    """
        WTForm for user registration.

        Used in: /register route

        After successful submission → user is saved to database and redirected
    """
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=30)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=6, message="Password must be at least 6 characters.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField("Sign Me Up!")




# TODO: Create a LoginForm to login existing users

class LoginForm(FlaskForm):
    """
    WTForm for user login.

    Used in: /login route

    Validates:
      - Email exists and is properly formatted, format of the string entered (it must contain @ and a domain name).
      - Password is provided
      - Actual password correctness is checked in the route using check_password_hash
    """
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")




# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    """
    Form for leaving comments using CKEditor (rich text).
    Only logged-in users can submit.
    """
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")




