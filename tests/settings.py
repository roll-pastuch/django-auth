DEBUG = False
SECRET_KEY = "tests"
ROOT_URLCONF = "tests.urls"
ALLOWED_HOSTS = ["testserver"]
MOCK_USER_EMAIL = ""
MOCK_USER_NAME = ""
MOCK_USER_ROLES = []

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "inertia",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django_auth.IdentityMiddleware",
    "inertia.middleware.InertiaMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
    }
]
