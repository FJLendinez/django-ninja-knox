from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth.signals import user_logged_in, user_logged_out
from ninja.responses import Response

from knox.models import AuthToken
from knox.schemas import Login

from ninja.router import Router

auth_router = Router()


@auth_router.post('/login/', auth=None)
def login(request, login_data: Login):
    user = authenticate(request,
                        username=login_data.username,
                        password=login_data.password)

    if not user:
        return Response(
            {"error": "Maximum amount of tokens allowed per user exceeded."},
            status=403)

    token_ttl = timedelta(hours=10)
    instance, token = AuthToken.objects.create(user, token_ttl)
    user_logged_in.send(sender=user.__class__,
                        request=request, user=user)
    return {"token": token}


@auth_router.post("/logout/")
def logout(request):
    request._auth.delete()
    user_logged_out.send(sender=request.auth.__class__,
                         request=request, user=request.auth)
    return Response(None, status=204)


@auth_router.post("/logoutall/")
def logout_all(request):
    request.auth.auth_token_set.all().delete()
    user_logged_out.send(sender=request.auth.__class__,
                         request=request, user=request.auth)
    return Response(None, status=204)
