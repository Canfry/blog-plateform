from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from functools import wraps
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap5
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Integer, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, EditPostForm, EditUserForm
from dotenv import load_dotenv
from variables import USERNAME, PASSWORD, today
from dataclasses import dataclass
from typing import List
from datetime import timedelta
import smtplib
import os

load_dotenv()

# Initialize Extension
class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

# Configure Extension
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('SQLALCHEMY_DATABASE_URI')
# Security for HTTPS
app.config['SESSION_COOKIE_SECURE'] = True
# Prevent malicious scripts
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
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
    subtitle: Mapped[str] = mapped_column(String(255), unique=True,nullable=False)
    posts: Mapped[List['BlogPost']] = relationship(back_populates="author", lazy='subquery', cascade='all, delete')
    comments = relationship('Comment', back_populates="author", lazy='subquery', cascade='all, delete')

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


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function


@app.route('/users_list')
@admin_only
@login_required
def users_list():
   users = db.session.execute(db.select(User))
   users_list = users.scalars()
   return render_template('users.html', users=users_list, logged_in=current_user.is_authenticated)


@app.route('/users_list/delete/<int:user_id>')
def delete_user_from_admin(user_id):
   user = db.session.execute(db.select(User).where(User.id == user_id))
   user_to_delete = user.scalar()
  #  print(user_to_delete.id)
   db.session.delete(user_to_delete)
   db.session.commit()
   return redirect(url_for('users_list'))


@app.route('/')
def home():
  print(request)
  logged_in = current_user.is_authenticated
  if logged_in:
     return redirect(url_for('get_all_posts'))
  return redirect(url_for('login'))

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
         subtitle = form.subtitle.data
      )

      db.session.add(new_user)
      db.session.commit()
      login_user(new_user)
      return redirect(url_for('get_all_posts'))
   return render_template('register.html', form=form, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/login', methods=['GET', 'POST'])
def login():
   url = request.path
   print(url)
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
   return render_template('login.html', form=form, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
  user = db.session.execute(db.select(User).where(User.id == user_id))
  user_profile = user.scalar()
  posts = user_profile.posts
  if user_profile.id == current_user.id:
    return redirect(url_for('get_my_posts'))
  return render_template('profile.html', user=user_profile, logged_in=current_user.is_authenticated, posts=posts)


@app.route('/user_account/<int:user_id>')
@login_required
def user_account(user_id):
  print(request.path)
  user = db.session.execute(db.select(User).where(User.id == user_id)).scalar()
  return render_template('user.html', user=user, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/user_account/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
  user = db.get_or_404(User, user_id, description='Sorry! No user with this id found in the database')
  edit_user_form = EditUserForm(
    email = user.email,
    name = user.name,
    subtitle = user.subtitle,
  )
  if edit_user_form.validate_on_submit():
    user.email = edit_user_form.email.data
    user.name = edit_user_form.name.data
    user.subtitle = edit_user_form.subtitle.data
    db.session.commit()
    return redirect(url_for('get_my_posts'))
    
  return render_template('edit-user.html', user=user, form=edit_user_form, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
  user = db.get_or_404(User, user_id, description='Sorry! No article with this id found in the database')
  db.session.delete(user)
  db.session.commit()
  session.clear()
  flash('Account deleted successfully')
  return redirect(url_for('register'))
  

@app.route('/all-posts')
@login_required
def get_all_posts():
  posts = db.session.execute(db.select(BlogPost)).scalars()
  all_posts = posts.fetchall()
  name = current_user.name
  # return redirect(url_for('login'))
  return render_template('index.html', name=name, posts=all_posts, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/my-posts')
@login_required
def get_my_posts():
   user_id = current_user.id
   name = current_user.name
   posts = db.session.execute(db.select(BlogPost).where(BlogPost.author_id == user_id)).scalars()
   all_posts = posts
   return render_template('user-posts.html', posts=all_posts, name=name, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def get_post(post_id):
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
     return redirect(url_for('get_post', post_id=post.id, post=post))
  
  return render_template('post.html', post=post, logged_in=current_user.is_authenticated, name=name, form=form, today=today, url=request.path)
  
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
      return render_template('make-post.html', form=form, logged_in=current_user.is_authenticated, url=request.path)


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
    post.author = current_user
    post.img_url = edit_form.img_url.data
    db.session.commit()
    return redirect(url_for('get_post', post_id=post.id))
    
  return render_template('edit-post.html', post=post, form=edit_form, logged_in=current_user.is_authenticated, url=request.path)


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
   post = db.get_or_404(BlogPost, post_id, description='Sorry! No article with this id found in the database')
   db.session.delete(post)
   db.session.commit()
   return redirect(url_for('get_all_posts'))


@app.route('/about')
def about():
  return render_template('about.html', logged_in=current_user.is_authenticated, url=request.path)


@app.route('/contact', methods=['GET', 'POST'])
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

  return render_template('contact.html', logged_in=current_user.is_authenticated, url=request.path)


@app.route('/form-submitted')
def form_submitted():
  return render_template('form-submitted.html', logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5500)