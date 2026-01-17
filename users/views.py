from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import JSONParser, FormParser
from .serializers import UserCreateSerializer, UserSerializer


class UserCreateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            UserSerializer(user).data,
            status=status.HTTP_201_CREATED
        )



class LoginView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # 🔒 Validação explícita (nunca deixa passar vazio)
        if not username or not password:
            return Response(
                {
                    "detail": "Username e senha são obrigatórios",
                    "code": "MISSING_CREDENTIALS"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)

        # 🔐 Credenciais inválidas
        if not user:
            return Response(
                {
                    "detail": "Usuário ou senha inválidos",
                    "code": "INVALID_CREDENTIALS"
                },
                status=status.HTTP_401_UNAUTHORIZED
            )

        refresh = RefreshToken.for_user(user)

        # ✅ Resposta consistente
        return Response(
            {
                "user": UserSerializer(user).data,
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            },
            status=status.HTTP_200_OK
        )



class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)
