# Welcome to Community Blog

Want to create a community blog platform where we can share our knowledge and learn from others. The project has a strong security configuration and a solid database.

# To start the project

1. Clone the project in the folder of your choice. Set up Python interpreter as Python 3.12
2. Set up a Python environment:

```
python3 -m venv thenameofyourchoice(usually venv or .venv)
# Then activate it:
source thenameyouchose/bin/activate
```

3. Install the packages:

```
pip install -r requirements.txt
```

4. You will have to set up your own secret key and SQL database URI to make it work locally. For development I've used SQLAlchemy because it was easy to migrate to PostgreSQL.

5. Run the code:

```
flask --app server run --debug
```

# Goals

- I've used Bootstrap for styling layouts and forms. WTForms to generate automatically the forms.
- I want to restyle the project using Tailwindcss.
- To add post you have to put an URL for your background image, I want to incorporate a way to upload an image file but was facing issues so for the moment it stays like this.
- Wanted to put MDEditor instead of CKEditor for the body of the create post form, but it didn't work. Would like to incorporate it to the project.
- Really want to make the project grow and add functionalities.
- You're invited to create pull requests for any suggestions or improvements on the project.
