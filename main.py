from crypt import methods
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os

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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
app.config['CKEDITOR_SERVE_LOCAL'] = False
Bootstrap5(app)


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # Foreign key and relationship to User
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    author: Mapped["User"] = relationship("User", back_populates="posts")

    # One-to-many relationship (BlogPost -> Comments)
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="post_comment")



class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(250), nullable=True)
    # Foreign key and relationship to User
    comment_author_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")

    # Foreign key and relationship to BlogPost
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    post_comment: Mapped["User"] = relationship("BlogPost", back_populates="comments")


# TODO: Create a User table for all your registered users.
# UserMixin is a helper class provided by Flask-Login that
# gives your user model the basic functionality Flask-Login expects
# — like checking if a user is authenticated, active, anonymous, and getting their ID.
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250),unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    type: Mapped[str] = mapped_column(String(100))
    # One-to-many relationship (User -> BlogPosts)
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    # One-to-many relationship (User -> Comments)
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="comment_author")



with app.app_context():
    db.create_all()

# If you don’t define @login_manager.user_loader,
# users won’t stay logged in across requests
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# If you want current user (or any user-related variable) to be available in all templates like about.html, contact.html, etc.,
# the best and cleanest solution is to use a context processor in Flask.
@app.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(current_user=current_user)
    return dict(current_user=None)

def admin_only(function):
    @wraps(function)
    #In order to work with routes that accept parameters,
    # the wrapper_function should accept *args, **kwargs
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.type == "Admin":
            return function(*args, **kwargs)
        else:
            abort(403)  # Forbidden
    return wrapper_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET','POST'])
def register():
    register_form = RegisterForm()
    email = register_form.email.data

    user = db.session.execute(db.select(User).where(User.email == email)).scalar()
    if user:
        flash("You've already signed up with this email. Log in instead!")
        return redirect(url_for('login'))
    if register_form.validate_on_submit():
        password = register_form.password.data
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        email = register_form.email.data
        name = register_form.name.data

        new_user = User(
            email=email,
            password=hash_and_salted_password,
            name=name,
            type="User"
        )

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html", register_form=register_form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET","POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if not user:
            flash("The email does not exist.")
            return redirect('login')
        elif not check_password_hash(user.password, password):
            flash("Password doesn't match.")
            return redirect('login')
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html",login_form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET","POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    comment_form = CommentForm()
    text = comment_form.comment.data
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment.")
            return redirect(url_for('login'))

        new_comment = Comment(
            text=text,
            comment_author=current_user,
            post_comment=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=requested_post.id))

    current_post_comments = Comment.query.filter_by(post_id=post_id).all()

    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='identicon',
                        force_default=False,
                        use_ssl=True,
                        base_url=None)

    return render_template("post.html",
                           post=requested_post,
                           comment_form=comment_form,
                           comments=current_post_comments,
                           gravatar=gravatar)


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


if __name__ == "__main__":
    app.run(debug=False)
