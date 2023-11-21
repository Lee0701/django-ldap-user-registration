from django import forms
from django.conf import settings
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import User

from crispy_forms.bootstrap import Field
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Div, Fieldset

from captcha.fields import ReCaptchaField
from django_countries.fields import CountryField

from django.utils.translation import gettext_lazy as _

from .models import Institution
from .ldap import LDAPOperations


class UserRegisterForm(forms.Form):
    # mandatory schema fields during registration
    full_name = forms.CharField(required=False, max_length=255)
    username = forms.CharField(required=True,
                               min_length=3,
                               max_length=30,
                               label=_('username'),
                               validators=[UnicodeUsernameValidator()])
    email = forms.EmailField(required=True, label=_('email address'))
    password = forms.CharField(label=_('password'), widget=forms.PasswordInput, min_length=8)
    password1 = forms.CharField(label=_('confirm password'), widget=forms.PasswordInput, min_length=8)
    # hide captcha field during unit tests
    if not settings.TESTING:
        captcha = ReCaptchaField()

    def __init__(self, *args, **kwargs):
        super(UserRegisterForm, self).__init__(*args, **kwargs)
        self.ldap_ops = LDAPOperations()
        self.helper = FormHelper()
        self.helper.form_id = 'id-user-data-form'
        self.helper.form_method = 'post'
        # self.helper.form_action = 'register'
        self.helper.add_input(Submit('submit', _('submit'), css_class='btn-success'))
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-md-2'
        self.helper.field_class = 'col-md-8'
        self.helper.error_text_inline = False
        self.helper.layout = Layout()

        self.helper.layout.append(Fieldset(_('basic data'), 'email'))
        self.helper.layout.append(Fieldset(_('login details'),
                'username', 'password', 'password1'))
        if settings.RECAPTCHA_PUBLIC_KEY and settings.RECAPTCHA_PRIVATE_KEY is not None:
            self.helper.layout.append(Fieldset(_('spam control'), 'captcha'))

    def clean_username(self):
        username = self.cleaned_data['username']

        # check username existence in local storage DB
        query_set = User.objects.filter(username=username)

        # check username existence in LDAP
        result = self.ldap_ops.check_attribute('uid', username)
        if result or query_set:
            raise forms.ValidationError("Username " + username + " is not available (in use)",
                                        code='username_exists_ldap')

        return username

    def clean_email(self):
        mail = self.cleaned_data['email']

        # check for email existence in local storage DB
        query_set = User.objects.filter(email=mail)

        # check email existence in LDAP
        result = self.ldap_ops.check_attribute('mail', mail)
        if result or query_set:
            raise forms.ValidationError("Email " + mail + " is not available (in use)",
                                        code='email_exists_ldap')

        return mail

    def clean(self):

        # Check for password matching
        password = self.cleaned_data.get('password')
        password1 = self.cleaned_data.get('password1')

        if password != password1:
            self._errors["password"] = self.error_class(["Passwords do not match"])

        return self.cleaned_data


class PasswordResetForm(forms.Form):
    # hide captcha field during unit tests
    if not settings.TESTING:
        captcha = ReCaptchaField()
    email = forms.EmailField(
        required=True,
        label='ENTER YOUR EMAIL',
        help_text="An email will be sent to the address you specify, containing a link that will allow you to change\
         your old password. "
    )

    def __init__(self, *args, **kwargs):
        super(PasswordResetForm, self).__init__(*args, **kwargs)
        self.ldap_ops = LDAPOperations()
        self.helper = FormHelper()
        self.helper.form_id = 'id-password-reset-form'
        self.helper.form_method = 'post'
        self.helper.add_input(Submit('submit', _('submit'), css_class='btn-warning'))
        # self.helper.form_class = 'form-horizontal'
        # self.helper.label_class = 'col-md-2'
        # self.helper.field_class = 'col-md-8'
        self.helper.error_text_inline = False
        self.helper.layout = Layout(
            Field('email', placeholder='Your E-mail')
        )
        if settings.RECAPTCHA_PUBLIC_KEY and settings.RECAPTCHA_PRIVATE_KEY is not None:
            self.helper.layout.append(
                Field('captcha')
            )

    def clean_email(self):
        mail = self.cleaned_data['email']
        # check for email existence in local storage DB
        query_set = User.objects.filter(email=mail, is_active=True)

        # check email existence in LDAP
        result = self.ldap_ops.check_attribute('mail', mail)
        if not result and not query_set:
            raise forms.ValidationError("This email address doesn't have an associated user account. \
            Please make sure you have registered, before proceeding.",
                                        code='email_exists_ldap')
        return mail


class PasswordResetEditForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, min_length=8, label='New password')
    password1 = forms.CharField(widget=forms.PasswordInput, min_length=8, label='New password confirmation')

    def __init__(self, *args, **kwargs):
        super(PasswordResetEditForm, self).__init__(*args, **kwargs)
        self.ldap_ops = LDAPOperations()
        self.helper = FormHelper()
        self.helper.form_id = 'id-password-reset-edit-form'
        self.helper.form_method = 'post'
        self.helper.add_input(Submit('submit', _('submit'), css_class='btn-warning'))
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-md-4'
        self.helper.field_class = 'col-md-8'
        self.helper.error_text_inline = False
        self.helper.layout = Layout(
            Fieldset('Please enter your new password',
                     Field('password'),
                     Field('password1')
                     )
        )

    def clean(self):
        # Check for password matching

        password = self.cleaned_data.get('password')
        password1 = self.cleaned_data.get('password1')

        if password != password1:
            self._errors["password"] = self.error_class(["Passwords do not match"])

        return self.cleaned_data
