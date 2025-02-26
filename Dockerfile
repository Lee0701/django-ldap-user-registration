FROM python:3.11
WORKDIR /usr/src/app

RUN apt update && apt install -y libsasl2-dev python-dev-is-python3 libldap2-dev libssl-dev gettext

COPY requirements.pip ./
RUN pip install -r requirements.pip

COPY . .

RUN python manage.py migrate
RUN django-admin compilemessages --ignore=env

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "django_ldap_user_registration.wsgi:application"]
