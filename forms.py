# from flask_mdeditor import MDEditorField, MDEditor
from flask_ckeditor import CKEditorField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_wtf import FlaskForm

style = {'class': 'btn btn-warning'}

# Create Post Form
class CreatePostForm(FlaskForm):
   title = StringField('Title', validators=[DataRequired()])
   subtitle = StringField('Subtitle', validators=[DataRequired()])
   img_url = StringField('Cover Image', validators=[DataRequired(), URL()])
   body = CKEditorField('Body', validators=[DataRequired()])
   submit = SubmitField(label='Add Post', render_kw=style)

class EditPostForm(FlaskForm):
  title = StringField('Title', validators=[DataRequired()])
  subtitle = StringField('Subtitle', validators=[DataRequired()])
  img_url = StringField('Cover Image', validators=[DataRequired(), URL()])
  body = CKEditorField('Body', validators=[DataRequired()])
  submit = SubmitField("Edit Post", render_kw=style)

class RegisterForm(FlaskForm):
  email = StringField('Email', validators=[DataRequired()])
  password = PasswordField('Password', validators=[DataRequired()])
  name = StringField('Name', validators=[DataRequired()])
  submit = SubmitField("Register", render_kw=style)

class LoginForm(FlaskForm):
  email = StringField('Email', validators=[DataRequired()])
  password = PasswordField('Password', validators=[DataRequired()])
  submit = SubmitField("Login", render_kw=style)

class CommentForm(FlaskForm):
   body = CKEditorField('Comment', validators=[DataRequired()])
   submit = SubmitField(label='Add Comment', render_kw=style)