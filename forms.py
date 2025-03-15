from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, TextAreaField, IntegerField, SelectField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from flask_wtf.file import FileAllowed


class LoginForm(FlaskForm):
    email = StringField('Username/Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Length(min=6)])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(),
                                        EqualTo('password')])
    full_name = StringField('Full Name', validators=[DataRequired()])
    qualification = StringField('Qualification', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])


class SubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])


class ChapterForm(FlaskForm):
    subject_id = SelectField('Subject',
                             coerce=int,
                             validators=[DataRequired()])
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])


class QuizForm(FlaskForm):
    chapter_id = SelectField('Chapter',
                             coerce=int,
                             validators=[DataRequired()])
    date_of_quiz = DateField('Quiz Date', validators=[DataRequired()])
    time_duration = IntegerField('Duration (minutes)',
                                 validators=[DataRequired()])
    remarks = TextAreaField('Remarks')


class QuestionForm(FlaskForm):
    quiz_id = SelectField('Quiz', coerce=int, validators=[DataRequired()])
    question_statement = TextAreaField('Question', validators=[DataRequired()])
    question_image = FileField(
        'Question Image',
        validators=[FileAllowed(['jpg', 'png', 'gif'], 'Images only!')])
    option_1 = StringField('Option 1', validators=[DataRequired()])
    option_2 = StringField('Option 2', validators=[DataRequired()])
    option_3 = StringField('Option 3', validators=[DataRequired()])
    option_4 = StringField('Option 4', validators=[DataRequired()])
    correct_option = SelectField('Correct Option',
                                 choices=[(1, '1'), (2, '2'), (3, '3'),
                                          (4, '4')],
                                 coerce=int,
                                 validators=[DataRequired()])


class QuestionImportForm(FlaskForm):
    quiz_id = SelectField('Quiz', coerce=int, validators=[DataRequired()])
    file = FileField('CSV/Excel File',
                     validators=[
                         DataRequired(),
                         FileAllowed(['csv', 'xlsx'],
                                     'CSV or Excel files only!')
                     ])


class UserProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    full_name = StringField('Full Name', validators=[DataRequired()])
    qualification = StringField('Qualification')
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        Optional(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Update Profile')

class AdminProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
