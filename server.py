from flask import Flask, render_template, request, redirect, url_for, flash, abort
# from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, logout_user, LoginManager, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, ForeignKey
from dataclasses import dataclass
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import datetime
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, EditPostForm
from functools import wraps
from typing import List
from dotenv import load_dotenv
import smtplib
import os

load_dotenv()

USERNAME = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')

today = datetime.now().strftime("%B %d, %Y")

# Initialize Extension
class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

# Configure Extension
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('SQLALCHEMY_DATABASE_URI')
# mdeditor = MDEditor(app)
ckeditor = CKEditor(app)
db.init_app(app)
Bootstrap5(app)

# Flask LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Create user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


## User TABLE Configuration
@dataclass
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True,nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    posts: Mapped[List['BlogPost']] = relationship(back_populates="author", cascade='all, delete')
    comments = relationship('Comment', back_populates="author", cascade='all, delete')

##BlogPosts TABLE Configuration
@dataclass
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author: Mapped['User'] = relationship(back_populates='posts')
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments: Mapped[List['Comment']] = relationship(back_populates='posts', cascade='all, delete')

##BlogPosts TABLE Configuration
@dataclass
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author: Mapped['User'] = relationship(back_populates='comments')
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    posts: Mapped['BlogPost'] = relationship(back_populates='comments')
    

with app.app_context():
    db.create_all()


#Create admin-only decorator
# def admin_only(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        # if current_user.id != 1:
        #     return abort(403)
        #Otherwise continue with the route function
    #     return f(*args, **kwargs)        
    # return decorated_function


@app.route('/')
def home():
  return redirect('login')

@app.route('/all-posts')
@login_required
def get_all_posts():
  posts = db.session.execute(db.select(BlogPost)).scalars()
  all_posts = posts.fetchall()
  name = current_user.name
  # return redirect(url_for('login'))
  return render_template('index.html', name=name, posts=all_posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
   if form.validate_on_submit():
      email = form.email.data
      result = db.session.execute(db.select(User).where(User.email == email))
      user = result.scalar()

      if user:
        flash("You've already signed up with that email, log in instead!")
        return redirect(url_for('login'))


      hash_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)

      new_user = User(
         email = form.email.data,
         password = hash_password,
         name = form.name.data,
      )

      db.session.add(new_user)
      db.session.commit()
      login_user(new_user)
      return redirect(url_for('get_all_posts'))
   return render_template('register.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if request.method == 'POST':
      email = request.form.get('email')
      password = request.form.get('password')

      result = db.session.execute(db.select(User).where(User.email == email))
      user = result.scalar()

      if not user:
         flash('No exisitng account with that email')
         return redirect(url_for('login'))
      
      elif not check_password_hash(user.password, password):
         flash('Invalid credentials')
         return redirect(url_for('login'))

      else:
        login_user(user)
        return redirect(url_for('get_all_posts')) 
   return render_template('login.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/about')
@login_required
def about():
  return render_template('about.html', logged_in=current_user.is_authenticated)


@app.route('/form-submitted')
@login_required
def form_submitted():
  return render_template('form-submitted.html', logged_in=current_user.is_authenticated)


@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
  if request.method == 'POST':
    name = request.form.get('name')
    email = request.form.get('email')
    tel = request.form.get('tel')
    message = request.form.get('message')
    with smtplib.SMTP('smtp.gmail.com') as connection:
            connection.starttls()
            connection.login(user=USERNAME, password=PASSWORD)
            connection.sendmail(from_addr=USERNAME, to_addrs='info@frydesign.fr', msg=f'subject:New contact message\n\nName: {name}\nEmail: {email}\nTel: {tel}\nMessage: {message}')
    return redirect('/form-submitted')

  return render_template('contact.html', logged_in=current_user.is_authenticated)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def get_post(post_id):
  result = db.session.execute(db.select(Comment)).scalars()
  comments = result.fetchall()
  post = db.get_or_404(BlogPost, post_id, description='Sorry!! There is no post with this ID in our database.')
  name = current_user.name
  form = CommentForm()
  if form.validate_on_submit():
     
     comment = Comment(
        text = request.form.get('body'),
        author_id=current_user.id,
        post_id=post.id
     )
     db.session.add(comment)
     db.session.commit()
     return redirect(url_for('get_post', post_id=post.id))
  
  return render_template('post.html', post=post, logged_in=current_user.is_authenticated, name=name, form=form)
  
@app.route('/new-post', methods=['GET', 'POST'])
@login_required
def add_post():
   form = CreatePostForm()
   if form.validate_on_submit():
    new_post = BlogPost(
        title = request.form.get('title'),
        subtitle = request.form.get('subtitle'),
        date = today,
        body = request.form.get('body'),
        author = current_user,
        img_url = request.form.get('img_url')
    )
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))
   else:
      return render_template('make-post.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
  post = db.get_or_404(BlogPost, post_id, description='Sorry! No article with this id found in the database')
  edit_form = EditPostForm(
    title = post.title,
    subtitle = post.subtitle,
    img_url = post.img_url,
    author = post.author,
    body = post.body
  )
  if edit_form.validate_on_submit():
    post.title = edit_form.title.data
    post.subtitle = edit_form.subtitle.data
    post.body = edit_form.body.data
    post.author = edit_form.author.data
    post.img_url = edit_form.img_url.data
    db.session.commit()
    return redirect(url_for('get_post', post_id=post.id))
    
  return render_template('edit-post.html', post=post, form=edit_form, logged_in=current_user.is_authenticated)


@app.route('/delete/<int:post_id>')
@login_required
def delete_post(post_id):
   post = db.get_or_404(BlogPost, post_id, description='Sorry! No article with this id found in the database')
   db.session.delete(post)
   db.session.commit()
   return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True, port=5500)