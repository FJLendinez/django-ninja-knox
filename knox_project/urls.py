from django.urls import path
from ninja import NinjaAPI

from knox.auth import KnoxAuth
from knox.views import auth_router

api = NinjaAPI(auth=KnoxAuth())
api.add_router('', auth_router)


@api.get("/mock/")
def mock():
    return {"hello": "world"}


urlpatterns = {
    path('api/', api.urls)
}
